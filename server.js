import express from "express";
import http from "http";
import crypto from "crypto";
import dns from "dns/promises";
import net from "net";
import { WebSocketServer } from "ws";
import { parse as parseCookie } from "cookie";

const app = express();
const server = http.createServer(app);

const PORT = Number(process.env.PORT || 10000);
const PROXY_KEY = process.env.PROXY_KEY || "";
const REQUEST_TIMEOUT = Number(process.env.REQUEST_TIMEOUT || 30000);
const MAX_BODY_SIZE = Number(process.env.MAX_BODY_SIZE || 10 * 1024 * 1024);

// Optional:
// PROXY_ALLOWLIST=example.com,example.org
//
// If empty, public HTTP/HTTPS destinations are allowed.
// Private/local destinations are always blocked.
const ALLOWLIST = (process.env.PROXY_ALLOWLIST || "")
  .split(",")
  .map((x) => x.trim().toLowerCase())
  .filter(Boolean);

const UPSTREAM_USER_AGENT =
  process.env.PROXY_USER_AGENT ||
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36";

const sessions = new Map();

app.disable("x-powered-by");

app.use(
  express.json({
    limit: `${Math.ceil(MAX_BODY_SIZE / 1024 / 1024)}mb`,
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: `${Math.ceil(MAX_BODY_SIZE / 1024 / 1024)}mb`,
  })
);

function randomId(bytes = 18) {
  return crypto.randomBytes(bytes).toString("hex");
}

function getSessionId(req) {
  const cookies = parseCookie(req.headers.cookie || "");
  return cookies.proxy_session || null;
}

function getOrCreateSession(req, res) {
  let id = getSessionId(req);

  if (!id || !sessions.has(id)) {
    id = randomId();
    sessions.set(id, {
      cookies: new Map(),
      createdAt: Date.now(),
      lastUsed: Date.now(),
    });

    res.cookie("proxy_session", id, {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      maxAge: 24 * 60 * 60 * 1000,
    });
  }

  const session = sessions.get(id);
  session.lastUsed = Date.now();

  return session;
}

function cleanupSessions() {
  const now = Date.now();

  for (const [id, session] of sessions) {
    if (now - session.lastUsed > 24 * 60 * 60 * 1000) {
      sessions.delete(id);
    }
  }
}

setInterval(cleanupSessions, 60 * 60 * 1000).unref();

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);

  if (parts.length !== 4 || parts.some(Number.isNaN)) {
    return false;
  }

  const [a, b] = parts;

  return (
    a === 10 ||
    a === 127 ||
    a === 0 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}

function isPrivateIPv6(ip) {
  const normalized = ip.toLowerCase();

  return (
    normalized === "::" ||
    normalized === "::1" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe8") ||
    normalized.startsWith("fe9") ||
    normalized.startsWith("fea") ||
    normalized.startsWith("feb")
  );
}

function isPrivateAddress(address) {
  const family = net.isIP(address);

  if (family === 4) {
    return isPrivateIPv4(address);
  }

  if (family === 6) {
    return isPrivateIPv6(address);
  }

  return false;
}

function hostnameAllowed(hostname) {
  const host = hostname.toLowerCase().replace(/\.$/, "");

  if (ALLOWLIST.length === 0) {
    return true;
  }

  return ALLOWLIST.some(
    (allowed) => host === allowed || host.endsWith(`.${allowed}`)
  );
}

async function validateDestination(url) {
  let parsed;

  try {
    parsed = new URL(url);
  } catch {
    throw new Error("Invalid URL");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only HTTP and HTTPS destinations are supported");
  }

  if (parsed.username || parsed.password) {
    throw new Error("URLs containing credentials are not allowed");
  }

  const hostname = parsed.hostname.toLowerCase();

  if (!hostnameAllowed(hostname)) {
    throw new Error("Destination is not on the proxy allowlist");
  }

  // Block obvious local hostnames.
  if (
    hostname === "localhost" ||
    hostname === "localhost.localdomain" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname === "ip6-localhost"
  ) {
    throw new Error("Local destinations are blocked");
  }

  // Direct IP address.
  if (net.isIP(hostname)) {
    if (isPrivateAddress(hostname)) {
      throw new Error("Private/internal destinations are blocked");
    }

    return parsed;
  }

  // Resolve the hostname and make sure it does not resolve to
  // a private/internal address.
  let addresses;

  try {
    addresses = await dns.lookup(hostname, {
      all: true,
      verbatim: true,
    });
  } catch {
    throw new Error("Unable to resolve destination hostname");
  }

  if (!addresses.length) {
    throw new Error("Destination hostname did not resolve");
  }

  for (const address of addresses) {
    if (isPrivateAddress(address.address)) {
      throw new Error("Destination resolves to a private/internal address");
    }
  }

  return parsed;
}

function getForwardHeaders(req, session, targetUrl) {
  const headers = new Headers();

  const allowedRequestHeaders = [
    "accept",
    "accept-language",
    "cache-control",
    "content-type",
    "if-match",
    "if-modified-since",
    "if-none-match",
    "if-unmodified-since",
    "pragma",
    "range",
    "referer",
    "user-agent",
  ];

  for (const name of allowedRequestHeaders) {
    const value = req.headers[name];

    if (value) {
      headers.set(name, Array.isArray(value) ? value.join(", ") : value);
    }
  }

  headers.set("user-agent", UPSTREAM_USER_AGENT);

  if (!headers.has("accept")) {
    headers.set(
      "accept",
      "text/html,application/xhtml+xml,application/xml;q=0.9," +
        "image/avif,image/webp,image/apng,*/*;q=0.8"
    );
  }

  if (!headers.has("accept-language")) {
    headers.set("accept-language", "en-US,en;q=0.9");
  }

  const storedCookies = [...session.cookies.entries()]
    .map(([name, value]) => `${name}=${value}`)
    .join("; ");

  if (storedCookies) {
    headers.set("cookie", storedCookies);
  }

  // Forward a useful referrer when the client supplies one.
  if (req.headers.referer) {
    try {
      const ref = new URL(req.headers.referer);

      if (["http:", "https:"].includes(ref.protocol)) {
        headers.set("referer", ref.href);
      }
    } catch {
      // Ignore invalid referrer.
    }
  }

  // Host is generated by fetch for the destination.
  headers.delete("host");

  // These are hop-by-hop headers and should not be forwarded.
  for (const name of [
    "connection",
    "proxy-connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
  ]) {
    headers.delete(name);
  }

  return headers;
}

function storeUpstreamCookies(response, session) {
  if (typeof response.headers.getSetCookie !== "function") {
    return;
  }

  const setCookies = response.headers.getSetCookie();

  for (const rawCookie of setCookies) {
    const firstPart = rawCookie.split(";")[0];
    const separator = firstPart.indexOf("=");

    if (separator === -1) {
      continue;
    }

    const name = firstPart.slice(0, separator).trim();
    const value = firstPart.slice(separator + 1).trim();

    if (name) {
      session.cookies.set(name, value);
    }
  }
}

function makeProxyUrl(url) {
  return `/proxy?url=${encodeURIComponent(url)}`;
}

function rewriteHtml(html, baseUrl) {
  // Remove CSP meta tags that would prevent resources from loading
  // through the proxy.
  html = html.replace(
    /<meta\b[^>]*http-equiv\s*=\s*["']content-security-policy["'][^>]*>/gi,
    ""
  );

  html = html.replace(
    /<meta\b[^>]*http-equiv\s*=\s*["']content-security-policy-report-only["'][^>]*>/gi,
    ""
  );

  function rewriteAttribute(match, prefix, quote, value) {
    const trimmed = value.trim();

    if (
      !trimmed ||
      trimmed.startsWith("#") ||
      trimmed.startsWith("data:") ||
      trimmed.startsWith("blob:") ||
      trimmed.startsWith("javascript:") ||
      trimmed.startsWith("mailto:") ||
      trimmed.startsWith("tel:")
    ) {
      return match;
    }

    try {
      const absolute = new URL(trimmed, baseUrl);

      if (!["http:", "https:"].includes(absolute.protocol)) {
        return match;
      }

      return `${prefix}${quote}${makeProxyUrl(absolute.href)}${quote}`;
    } catch {
      return match;
    }
  }

  html = html.replace(
    /(\b(?:href|src|action|poster)\s*=\s*)(["'])([^"']+)\2/gi,
    (match, prefix, quote, value) =>
      rewriteAttribute(match, prefix, quote, value)
  );

  html = html.replace(
    /\b(srcset\s*=\s*)(["'])([^"']+)\2/gi,
    (match, prefix, quote, value) => {
      const rewritten = value
        .split(",")
        .map((part) => {
          const pieces = part.trim().split(/\s+/);
          const source = pieces.shift();

          if (!source) {
            return part;
          }

          try {
            const absolute = new URL(source, baseUrl);

            if (!["http:", "https:"].includes(absolute.protocol)) {
              return part;
            }

            return [
              makeProxyUrl(absolute.href),
              ...pieces,
            ].join(" ");
          } catch {
            return part;
          }
        })
        .join(", ");

      return `${prefix}${quote}${rewritten}${quote}`;
    }
  );

  html = html.replace(
    /(<base\b[^>]*\bhref\s*=\s*)(["'])([^"']+)\2/gi,
    (match, prefix, quote, value) => {
      try {
        const absolute = new URL(value, baseUrl);

        if (!["http:", "https:"].includes(absolute.protocol)) {
          return match;
        }

        return `${prefix}${quote}${makeProxyUrl(absolute.href)}${quote}`;
      } catch {
        return match;
      }
    }
  );

  return html;
}

function stripHopByHopResponseHeaders(res) {
  for (const header of [
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
  ]) {
    res.removeHeader(header);
  }
}

function copyResponseHeaders(upstream, res) {
  const blocked = new Set([
    "content-length",
    "content-encoding",
    "transfer-encoding",
    "connection",
    "keep-alive",
    "upgrade",
    "content-security-policy",
    "content-security-policy-report-only",
    "x-frame-options",
  ]);

  for (const [name, value] of upstream.headers.entries()) {
    if (!blocked.has(name.toLowerCase())) {
      res.setHeader(name, value);
    }
  }

  stripHopByHopResponseHeaders(res);
}

function checkProxyKey(req, res) {
  if (!PROXY_KEY) {
    return true;
  }

  const supplied =
    req.headers["x-proxy-key"] ||
    req.query.key ||
    "";

  if (supplied !== PROXY_KEY) {
    res.status(401).json({
      error: "Unauthorized",
      message: "A valid proxy key is required.",
    });

    return false;
  }

  return true;
}

function getRequestBody(req) {
  if (["GET", "HEAD"].includes(req.method)) {
    return undefined;
  }

  if (req.body === undefined || req.body === null) {
    return undefined;
  }

  const contentType = String(req.headers["content-type"] || "");

  if (contentType.includes("application/json")) {
    return JSON.stringify(req.body);
  }

  if (contentType.includes("application/x-www-form-urlencoded")) {
    return new URLSearchParams(req.body).toString();
  }

  if (typeof req.body === "string") {
    return req.body;
  }

  return JSON.stringify(req.body);
}

/*
 * Home
 */
app.get("/", (req, res) => {
  res.redirect("/browser");
});

/*
 * Simple login/session page
 */
app.get("/login", (req, res) => {
  const session = getOrCreateSession(req, res);

  res.send(`
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Proxy Session</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      max-width: 800px;
      margin: 50px auto;
      padding: 20px;
      background: #f5f5f5;
    }

    .box {
      background: white;
      padding: 25px;
      border-radius: 12px;
      box-shadow: 0 4px 20px rgba(0,0,0,.08);
    }

    code {
      word-break: break-all;
    }
  </style>
</head>
<body>
  <div class="box">
    <h1>Proxy session</h1>
    <p>Session created successfully.</p>
    <p><strong>Session:</strong></p>
    <code>${escapeHtml(
      [...sessions.entries()].find(([, value]) => value === session)?.[0] ||
        "active"
    )}</code>

    <p><a href="/browser">Open proxy browser</a></p>
    <p><a href="/session">Session diagnostics</a></p>
  </div>
</body>
</html>
`);
});

/*
 * Session diagnostics
 */
app.get("/session", (req, res) => {
  const sessionId = getSessionId(req);

  if (!sessionId || !sessions.has(sessionId)) {
    return res.status(401).send(`
      <h1>No proxy session</h1>
      <p><a href="/login">Create session</a></p>
    `);
  }

  const session = sessions.get(sessionId);

  res.json({
    authenticated: true,
    sessionCreated: new Date(session.createdAt).toISOString(),
    sessionLastUsed: new Date(session.lastUsed).toISOString(),
    upstreamCookies: session.cookies.size,
    endpoints: {
      browser: "/browser",
      proxy: "/proxy?url=https://example.com",
      health: "/health",
    },
  });
});

/*
 * API session check
 */
app.get("/api/session", (req, res) => {
  const sessionId = getSessionId(req);

  if (!sessionId || !sessions.has(sessionId)) {
    return res.status(401).json({
      authenticated: false,
    });
  }

  res.json({
    authenticated: true,
  });
});

/*
 * Browser UI
 */
app.get("/browser", (req, res) => {
  res.send(`
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>VPS Web Proxy</title>

  <style>
    * {
      box-sizing: border-box;
    }

    body {
      margin: 0;
      background: #111;
      color: #fff;
      font-family: Arial, sans-serif;
    }

    .toolbar {
      height: 62px;
      display: flex;
      align-items: center;
      gap: 8px;
      padding: 10px;
      background: #1d1d1d;
      border-bottom: 1px solid #333;
    }

    button {
      height: 40px;
      padding: 0 14px;
      border: 0;
      border-radius: 8px;
      cursor: pointer;
      background: #333;
      color: white;
    }

    button:hover {
      background: #444;
    }

    form {
      display: flex;
      flex: 1;
      gap: 8px;
    }

    input {
      flex: 1;
      min-width: 0;
      height: 40px;
      border: 1px solid #444;
      border-radius: 8px;
      background: #111;
      color: white;
      padding: 0 12px;
      outline: none;
    }

    iframe {
      display: block;
      width: 100%;
      height: calc(100vh - 62px);
      border: 0;
      background: white;
    }
  </style>
</head>

<body>
  <div class="toolbar">
    <button onclick="goBack()">←</button>
    <button onclick="goForward()">→</button>
    <button onclick="reloadFrame()">↻</button>

    <form id="form">
      <input
        id="url"
        autocomplete="off"
        placeholder="https://example.com"
        value="https://example.com"
      >
      <button type="submit">Go</button>
    </form>
  </div>

  <iframe id="frame"></iframe>

  <script>
    const input = document.getElementById("url");
    const frame = document.getElementById("frame");
    const form = document.getElementById("form");

    function normalizeUrl(value) {
      value = value.trim();

      if (!value) {
        return "https://example.com";
      }

      if (!/^https?:\\/\\//i.test(value)) {
        value = "https://" + value;
      }

      return value;
    }

    function navigate(value) {
      const target = normalizeUrl(value);
      input.value = target;
      frame.src = "/proxy?url=" + encodeURIComponent(target);
    }

    form.addEventListener("submit", (event) => {
      event.preventDefault();
      navigate(input.value);
    });

    frame.addEventListener("load", () => {
      try {
        input.value = frame.contentWindow.location.href;
      } catch {
        // Cross-origin access is intentionally unavailable.
      }
    });

    function reloadFrame() {
      frame.contentWindow.location.reload();
    }

    function goBack() {
      frame.contentWindow.history.back();
    }

    function goForward() {
      frame.contentWindow.history.forward();
    }

    navigate(input.value);
  </script>
</body>
</html>
`);
});

/*
 * Main proxy endpoint
 */
app.all("/proxy", async (req, res) => {
  if (!checkProxyKey(req, res)) {
    return;
  }

  const target = req.query.url;

  if (typeof target !== "string" || !target.trim()) {
    return res.status(400).json({
      error: "Missing URL",
      usage: "/proxy?url=https://example.com",
    });
  }

  let targetUrl;

  try {
    targetUrl = await validateDestination(target);
  } catch (error) {
    return res.status(403).json({
      error: "Destination blocked",
      message: error.message,
    });
  }

  const session = getOrCreateSession(req, res);

  const headers = getForwardHeaders(req, session, targetUrl);
  const body = getRequestBody(req);

  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(),
    REQUEST_TIMEOUT
  );

  try {
    console.log(
      `[PROXY] ${req.method} ${targetUrl.href}`
    );

    const upstream = await fetch(targetUrl.href, {
      method: req.method,
      headers,
      body,
      redirect: "manual",
      signal: controller.signal,
    });

    storeUpstreamCookies(upstream, session);

    /*
     * Handle redirects ourselves so the next request still passes
     * through this proxy.
     */
    if (
      upstream.status >= 300 &&
      upstream.status < 400 &&
      upstream.headers.get("location")
    ) {
      const location = upstream.headers.get("location");

      try {
        const absolute = new URL(location, targetUrl);

        if (
          ["http:", "https:"].includes(absolute.protocol)
        ) {
          await validateDestination(absolute.href);

          return res.redirect(
            upstream.status,
            makeProxyUrl(absolute.href)
          );
        }
      } catch {
        // Fall through and return the original response.
      }
    }

    copyResponseHeaders(upstream, res);

    res.status(upstream.status);

    const contentType =
      upstream.headers.get("content-type") || "";

    /*
     * HTML must be rewritten so links, forms and assets continue
     * through the proxy.
     */
    if (contentType.includes("text/html")) {
      const text = await upstream.text();

      const rewritten = rewriteHtml(
        text,
        targetUrl.href
      );

      res.setHeader(
        "content-type",
        "text/html; charset=utf-8"
      );

      return res.send(rewritten);
    }

    /*
     * For non-HTML resources, stream the response directly.
     */
    if (upstream.body) {
      const reader = upstream.body.getReader();

      try {
        while (true) {
          const { done, value } = await reader.read();

          if (done) {
            break;
          }

          if (!res.write(Buffer.from(value))) {
            await new Promise((resolve) =>
              res.once("drain", resolve)
            );
          }
        }
      } finally {
        reader.releaseLock();
      }

      return res.end();
    }

    return res.end();
  } catch (error) {
    console.error("[PROXY ERROR]", error);

    if (error.name === "AbortError") {
      return res.status(504).json({
        error: "Gateway timeout",
        message: `The destination did not respond within ${REQUEST_TIMEOUT}ms.`,
      });
    }

    return res.status(502).json({
      error: "Bad gateway",
      message: error.message || "Unable to contact destination",
    });
  } finally {
    clearTimeout(timeout);
  }
});

/*
 * Health check
 */
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    service: "xcloud-test-proxy",
    uptime: process.uptime(),
    node: process.version,
    time: new Date().toISOString(),
  });
});

/*
 * Simple WebSocket test endpoint.
 *
 * This is intentionally a test stream rather than a generic WebSocket
 * tunneling service.
 */
const wss = new WebSocketServer({
  noServer: true,
});

server.on("upgrade", (request, socket, head) => {
  const url = new URL(
    request.url,
    `http://${request.headers.host || "localhost"}`
  );

  if (url.pathname !== "/stream") {
    socket.destroy();
    return;
  }

  wss.handleUpgrade(request, socket, head, (ws) => {
    wss.emit("connection", ws, request);
  });
});

wss.on("connection", (ws) => {
  let counter = 0;

  const interval = setInterval(() => {
    if (ws.readyState !== ws.OPEN) {
      clearInterval(interval);
      return;
    }

    counter++;

    const payload = Buffer.alloc(1024);

    payload.writeUInt32BE(counter, 0);
    payload.writeUInt32BE(Date.now() >>> 0, 4);

    ws.send(payload);

    if (counter >= 30) {
      clearInterval(interval);
      ws.close(1000, "Test stream complete");
    }
  }, 250);

  ws.on("close", () => {
    clearInterval(interval);
  });
});

/*
 * Generic 404
 */
app.use((req, res) => {
  res.status(404).json({
    error: "Not found",
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`
========================================
 XCloud VPS Proxy
========================================
 Port:        ${PORT}
 Node:        ${process.version}
 Timeout:     ${REQUEST_TIMEOUT}ms
 Allowlist:   ${
   ALLOWLIST.length ? ALLOWLIST.join(", ") : "public HTTP/HTTPS"
 }
 Proxy key:   ${PROXY_KEY ? "enabled" : "disabled"}

 Browser:
   /browser

 Proxy:
   /proxy?url=https://example.com

 Health:
   /health

 WebSocket test:
   /stream
========================================
`);
});
