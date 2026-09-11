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
const MAX_BODY_SIZE = Number(
  process.env.MAX_BODY_SIZE || 10 * 1024 * 1024
);

const ALLOWLIST = (process.env.PROXY_ALLOWLIST || "")
  .split(",")
  .map((x) => x.trim().toLowerCase())
  .filter(Boolean);

const UPSTREAM_USER_AGENT =
  process.env.PROXY_USER_AGENT ||
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
  "AppleWebKit/537.36 (KHTML, like Gecko) " +
  "Chrome/140.0.0.0 Safari/537.36";

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

/* =========================================================
   UTILITIES
   ========================================================= */

function randomId(bytes = 18) {
  return crypto.randomBytes(bytes).toString("hex");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
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

/* =========================================================
   SSRF PROTECTION
   ========================================================= */

function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);

  if (parts.length !== 4 || parts.some(Number.isNaN)) {
    return false;
  }

  const [a, b] = parts;

  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
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
    (allowed) =>
      host === allowed ||
      host.endsWith(`.${allowed}`)
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
    throw new Error(
      "Only HTTP and HTTPS destinations are supported"
    );
  }

  if (parsed.username || parsed.password) {
    throw new Error(
      "URLs containing credentials are not allowed"
    );
  }

  const hostname = parsed.hostname
    .toLowerCase()
    .replace(/\.$/, "");

  if (!hostnameAllowed(hostname)) {
    throw new Error(
      "Destination is not on the proxy allowlist"
    );
  }

  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname === "ip6-localhost"
  ) {
    throw new Error(
      "Local destinations are blocked"
    );
  }

  if (net.isIP(hostname)) {
    if (isPrivateAddress(hostname)) {
      throw new Error(
        "Private/internal destinations are blocked"
      );
    }

    return parsed;
  }

  let addresses;

  try {
    addresses = await dns.lookup(hostname, {
      all: true,
      verbatim: true,
    });
  } catch {
    throw new Error(
      "Unable to resolve destination hostname"
    );
  }

  if (!addresses.length) {
    throw new Error(
      "Destination hostname did not resolve"
    );
  }

  for (const address of addresses) {
    if (isPrivateAddress(address.address)) {
      throw new Error(
        "Destination resolves to a private/internal address"
      );
    }
  }

  return parsed;
}

/* =========================================================
   REQUEST HEADERS / COOKIES
   ========================================================= */

function getForwardHeaders(req, session) {
  const headers = new Headers();

  const allowedHeaders = [
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

  for (const name of allowedHeaders) {
    const value = req.headers[name];

    if (value) {
      headers.set(
        name,
        Array.isArray(value)
          ? value.join(", ")
          : value
      );
    }
  }

  headers.set(
    "user-agent",
    UPSTREAM_USER_AGENT
  );

  if (!headers.has("accept")) {
    headers.set(
      "accept",
      "text/html,application/xhtml+xml,application/xml;" +
        "q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
    );
  }

  if (!headers.has("accept-language")) {
    headers.set(
      "accept-language",
      "en-US,en;q=0.9"
    );
  }

  const cookies = [...session.cookies.entries()]
    .map(([name, value]) => `${name}=${value}`)
    .join("; ");

  if (cookies) {
    headers.set("cookie", cookies);
  }

  headers.delete("host");

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
  if (
    typeof response.headers.getSetCookie !==
    "function"
  ) {
    return;
  }

  const cookies =
    response.headers.getSetCookie();

  for (const rawCookie of cookies) {
    const firstPart = rawCookie.split(";")[0];
    const separator = firstPart.indexOf("=");

    if (separator === -1) {
      continue;
    }

    const name = firstPart
      .slice(0, separator)
      .trim();

    const value = firstPart
      .slice(separator + 1)
      .trim();

    if (name) {
      session.cookies.set(name, value);
    }
  }
}

/* =========================================================
   PROXY HELPERS
   ========================================================= */

function makeProxyUrl(url) {
  return `/proxy?url=${encodeURIComponent(url)}`;
}

function getRequestBody(req) {
  if (
    req.method === "GET" ||
    req.method === "HEAD"
  ) {
    return undefined;
  }

  if (
    req.body === undefined ||
    req.body === null
  ) {
    return undefined;
  }

  const contentType = String(
    req.headers["content-type"] || ""
  );

  if (
    contentType.includes("application/json")
  ) {
    return JSON.stringify(req.body);
  }

  if (
    contentType.includes(
      "application/x-www-form-urlencoded"
    )
  ) {
    return new URLSearchParams(req.body).toString();
  }

  if (typeof req.body === "string") {
    return req.body;
  }

  return JSON.stringify(req.body);
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
      message:
        "A valid proxy key is required.",
    });

    return false;
  }

  return true;
}

/* =========================================================
   HTML REWRITING
   ========================================================= */

function rewriteHtml(html, baseUrl) {
  html = html.replace(
    /<meta\b[^>]*http-equiv\s*=\s*["']content-security-policy["'][^>]*>/gi,
    ""
  );

  html = html.replace(
    /<meta\b[^>]*http-equiv\s*=\s*["']content-security-policy-report-only["'][^>]*>/gi,
    ""
  );

  function rewriteUrl(value) {
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
      return value;
    }

    try {
      const absolute = new URL(
        trimmed,
        baseUrl
      );

      if (
        !["http:", "https:"].includes(
          absolute.protocol
        )
      ) {
        return value;
      }

      return makeProxyUrl(
        absolute.href
      );
    } catch {
      return value;
    }
  }

  html = html.replace(
    /(\b(?:href|src|action|poster)\s*=\s*)(["'])([^"']+)\2/gi,
    (match, prefix, quote, value) => {
      return (
        prefix +
        quote +
        rewriteUrl(value) +
        quote
      );
    }
  );

  html = html.replace(
    /\b(srcset\s*=\s*)(["'])([^"']+)\2/gi,
    (match, prefix, quote, value) => {
      const rewritten = value
        .split(",")
        .map((part) => {
          const pieces = part
            .trim()
            .split(/\s+/);

          const source = pieces.shift();

          if (!source) {
            return part;
          }

          const newSource =
            rewriteUrl(source);

          return [
            newSource,
            ...pieces,
          ].join(" ");
        })
        .join(", ");

      return (
        prefix +
        quote +
        rewritten +
        quote
      );
    }
  );

  html = html.replace(
    /(<base\b[^>]*\bhref\s*=\s*)(["'])([^"']+)\2/gi,
    (match, prefix, quote, value) => {
      try {
        const absolute = new URL(
          value,
          baseUrl
        );

        return (
          prefix +
          quote +
          makeProxyUrl(
            absolute.href
          ) +
          quote
        );
      } catch {
        return match;
      }
    }
  );

  return html;
}

/* =========================================================
   HOME
   ========================================================= */

app.get("/", (req, res) => {
  res.redirect("/browser");
});

/* =========================================================
   LOGIN / SESSION
   ========================================================= */

app.get("/login", (req, res) => {
  getOrCreateSession(req, res);

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
a {
  color: #1769ff;
}
</style>
</head>
<body>
<div class="box">
<h1>Proxy session</h1>
<p>Your proxy session has been created.</p>
<p><a href="/browser">Open browser</a></p>
<p><a href="/session">View session</a></p>
</div>
</body>
</html>
`);
});

app.get("/session", (req, res) => {
  const sessionId = getSessionId(req);

  if (
    !sessionId ||
    !sessions.has(sessionId)
  ) {
    return res.status(401).json({
      authenticated: false,
    });
  }

  const session = sessions.get(
    sessionId
  );

  res.json({
    authenticated: true,
    createdAt: new Date(
      session.createdAt
    ).toISOString(),
    lastUsed: new Date(
      session.lastUsed
    ).toISOString(),
    upstreamCookies:
      session.cookies.size,
  });
});

app.get("/api/session", (req, res) => {
  const sessionId = getSessionId(req);

  if (
    !sessionId ||
    !sessions.has(sessionId)
  ) {
    return res.status(401).json({
      authenticated: false,
    });
  }

  res.json({
    authenticated: true,
  });
});

/* =========================================================
   PROXY BROWSER
   ========================================================= */

app.get("/browser", (req, res) => {
  res.send(`
<!doctype html>
<html>
<head>

<meta charset="utf-8">

<meta
  name="viewport"
  content="width=device-width,initial-scale=1"
>

<title>XCloud Browser</title>

<style>

* {
  box-sizing: border-box;
}

html,
body {
  margin: 0;
  width: 100%;
  height: 100%;
  overflow: hidden;
  font-family: Arial, sans-serif;
  background: #111;
  color: white;
}

.toolbar {
  height: 62px;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px;
  background: #181818;
  border-bottom: 1px solid #333;
}

button {
  height: 40px;
  padding: 0 14px;
  border: 0;
  border-radius: 8px;
  background: #303030;
  color: white;
  cursor: pointer;
  font-size: 14px;
}

button:hover {
  background: #414141;
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
  background: #101010;
  color: white;
  padding: 0 14px;
  font-size: 15px;
  outline: none;
}

input:focus {
  border-color: #777;
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

<button
  type="button"
  onclick="goBack()"
  title="Back"
>
←
</button>

<button
  type="button"
  onclick="goForward()"
  title="Forward"
>
→
</button>

<button
  type="button"
  onclick="reloadFrame()"
  title="Reload"
>
↻
</button>

<form id="form">

<input
  id="address"
  autocomplete="off"
  spellcheck="false"
  placeholder="Search DuckDuckGo or enter a URL"
>

<button type="submit">
Go
</button>

</form>

</div>

<iframe
  id="frame"
  title="Proxy Browser"
></iframe>

<script>

const form =
  document.getElementById("form");

const address =
  document.getElementById("address");

const frame =
  document.getElementById("frame");


function isUrl(value) {

  return /^https?:\\/\\//i.test(value);

}


function looksLikeDomain(value) {

  return /^[a-z0-9.-]+\\.[a-z]{2,}(?::\\d+)?(?:\\/.*)?$/i
    .test(value);

}


function buildDestination(value) {

  value = value.trim();

  if (!value) {

    return "https://duckduckgo.com/";

  }

  /*
   * Explicit URL.
   */

  if (isUrl(value)) {

    return value;

  }

  /*
   * Domain without protocol.
   */

  if (looksLikeDomain(value)) {

    return "https://" + value;

  }

  /*
   * Search query.
   *
   * DuckDuckGo search.
   */

  return (
    "https://duckduckgo.com/?q=" +
    encodeURIComponent(value) +
    "&kl=se-sv"
  );

}


function navigate(value) {

  const destination =
    buildDestination(value);

  address.value = destination;

  frame.src =
    "/proxy?url=" +
    encodeURIComponent(destination);

}


form.addEventListener(
  "submit",
  function(event) {

    event.preventDefault();

    navigate(address.value);

  }
);


function reloadFrame() {

  try {

    frame.contentWindow.location.reload();

  } catch {

    frame.src = frame.src;

  }

}


function goBack() {

  try {

    frame.contentWindow.history.back();

  } catch {}

}


function goForward() {

  try {

    frame.contentWindow.history.forward();

  } catch {}

}


/*
 * Start with DuckDuckGo.
 */

navigate("");

</script>

</body>
</html>
`);
});

/* =========================================================
   MAIN HTTP/HTTPS PROXY
   ========================================================= */

app.all("/proxy", async (req, res) => {

  if (!checkProxyKey(req, res)) {
    return;
  }

  const target = req.query.url;

  if (
    typeof target !== "string" ||
    !target.trim()
  ) {
    return res.status(400).json({
      error: "Missing URL",
      usage:
        "/proxy?url=https://example.com",
    });
  }

  let targetUrl;

  try {

    targetUrl =
      await validateDestination(target);

  } catch (error) {

    return res.status(403).json({
      error: "Destination blocked",
      message: error.message,
    });

  }

  const session =
    getOrCreateSession(req, res);

  const headers =
    getForwardHeaders(
      req,
      session
    );

  const body =
    getRequestBody(req);

  const controller =
    new AbortController();

  const timeout =
    setTimeout(
      () =>
        controller.abort(),
      REQUEST_TIMEOUT
    );

  try {

    console.log(
      `[PROXY] ${req.method} ${targetUrl.href}`
    );

    const upstream =
      await fetch(
        targetUrl.href,
        {
          method: req.method,
          headers,
          body,
          redirect: "manual",
          signal:
            controller.signal,
        }
      );

    storeUpstreamCookies(
      upstream,
      session
    );

    /*
     * Redirect handling.
     */

    if (
      upstream.status >= 300 &&
      upstream.status < 400
    ) {

      const location =
        upstream.headers.get(
          "location"
        );

      if (location) {

        try {

          const absolute =
            new URL(
              location,
              targetUrl
            );

          if (
            ["http:", "https:"].includes(
              absolute.protocol
            )
          ) {

            await validateDestination(
              absolute.href
            );

            return res.redirect(
              upstream.status,
              makeProxyUrl(
                absolute.href
              )
            );

          }

        } catch {
          // Return original response.
        }
      }
    }

    copyResponseHeaders(
      upstream,
      res
    );

    res.status(
      upstream.status
    );

    const contentType =
      upstream.headers.get(
        "content-type"
      ) || "";

    /*
     * HTML.
     */

    if (
      contentType.includes(
        "text/html"
      )
    ) {

      const text =
        await upstream.text();

      const rewritten =
        rewriteHtml(
          text,
          targetUrl.href
        );

      res.setHeader(
        "content-type",
        "text/html; charset=utf-8"
      );

      return res.send(
        rewritten
      );
    }

    /*
     * Everything else.
     */

    if (upstream.body) {

      const reader =
        upstream.body.getReader();

      try {

        while (true) {

          const {
            done,
            value,
          } =
            await reader.read();

          if (done) {
            break;
          }

          if (
            !res.write(
              Buffer.from(value)
            )
          ) {

            await new Promise(
              (resolve) =>
                res.once(
                  "drain",
                  resolve
                )
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

    console.error(
      "[PROXY ERROR]",
      error
    );

    if (
      error.name ===
      "AbortError"
    ) {

      return res.status(504).json({
        error:
          "Gateway timeout",
        message:
          `The destination did not respond within ${REQUEST_TIMEOUT}ms.`,
      });

    }

    return res.status(502).json({
      error:
        "Bad gateway",
      message:
        error.message ||
        "Unable to contact destination",
    });

  } finally {

    clearTimeout(timeout);

  }

});

/* =========================================================
   HEALTH
   ========================================================= */

app.get("/health", (req, res) => {

  res.json({
    status: "ok",
    service:
      "xcloud-test-proxy",
    uptime:
      process.uptime(),
    node:
      process.version,
    time:
      new Date().toISOString(),
  });

});

/* =========================================================
   WEBSOCKET TEST
   ========================================================= */

const wss =
  new WebSocketServer({
    noServer: true,
  });

server.on(
  "upgrade",
  (request, socket, head) => {

    const url =
      new URL(
        request.url,
        `http://${
          request.headers.host ||
          "localhost"
        }`
      );

    if (
      url.pathname !==
      "/stream"
    ) {

      socket.destroy();
      return;

    }

    wss.handleUpgrade(
      request,
      socket,
      head,
      (ws) => {

        wss.emit(
          "connection",
          ws,
          request
        );

      }
    );

  }
);

wss.on(
  "connection",
  (ws) => {

    let counter = 0;

    const interval =
      setInterval(
        () => {

          if (
            ws.readyState !==
            ws.OPEN
          ) {

            clearInterval(
              interval
            );

            return;
          }

          counter++;

          const payload =
            Buffer.alloc(1024);

          payload.writeUInt32BE(
            counter,
            0
          );

          payload.writeUInt32BE(
            Date.now() >>> 0,
            4
          );

          ws.send(payload);

          if (
            counter >= 30
          ) {

            clearInterval(
              interval
            );

            ws.close(
              1000,
              "Test stream complete"
            );

          }

        },
        250
      );

    ws.on(
      "close",
      () => {
        clearInterval(
          interval
        );
      }
    );

  }
);

/* =========================================================
   404
   ========================================================= */

app.use(
  (req, res) => {

    res.status(404).json({
      error: "Not found",
    });

  }
);

/* =========================================================
   START
   ========================================================= */

server.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(`
========================================
 XCloud VPS Proxy
========================================

Port:
  ${PORT}

Node:
  ${process.version}

Timeout:
  ${REQUEST_TIMEOUT}ms

Allowlist:
  ${
    ALLOWLIST.length
      ? ALLOWLIST.join(", ")
      : "Public HTTP/HTTPS"
  }

Proxy key:
  ${
    PROXY_KEY
      ? "Enabled"
      : "Disabled"
  }

Browser:
  /browser

Proxy:
  /proxy?url=https://example.com

Health:
  /health

WebSocket test:
  /stream

Search engine:
  DuckDuckGo

========================================
`);

  }
);
