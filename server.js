import express from "express";
import http from "http";
import crypto from "crypto";
import dns from "dns";
import dnsPromises from "dns/promises";
import { WebSocketServer } from "ws";

dns.setDefaultResultOrder("ipv4first");

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ noServer: true });

const PORT = Number(process.env.PORT || 10000);

const PROXY_KEY = process.env.PROXY_KEY || "";

const sessions = new Map();

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));

/* -------------------------------------------------------
   Basic helpers
------------------------------------------------------- */

function makeId(bytes = 24) {
  return crypto.randomBytes(bytes).toString("hex");
}

function escapeHtml(value = "") {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function getProxyKey(req) {
  return (
    req.headers["x-proxy-key"] ||
    req.query.key ||
    req.body?.key ||
    ""
  );
}

function requireProxyKey(req, res, next) {
  if (!PROXY_KEY) return next();

  if (getProxyKey(req) !== PROXY_KEY) {
    return res.status(401).json({
      error: "Unauthorized",
      message: "A valid proxy key is required."
    });
  }

  next();
}

function normalizeInput(input) {
  input = String(input || "").trim();

  if (!input) return null;

  if (/^https?:\/\//i.test(input)) {
    return input;
  }

  if (
    /^[a-z0-9.-]+\.[a-z]{2,}(\/.*)?$/i.test(input)
  ) {
    return `https://${input}`;
  }

  return `https://duckduckgo.com/?q=${encodeURIComponent(input)}&kl=se-sv`;
}

function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);

  if (parts.length !== 4 || parts.some(Number.isNaN)) {
    return false;
  }

  const [a, b] = parts;

  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;

  return false;
}

function isPrivateIPv6(ip) {
  const value = ip.toLowerCase();

  if (value === "::1") return true;
  if (value.startsWith("fc")) return true;
  if (value.startsWith("fd")) return true;
  if (value.startsWith("fe80:")) return true;

  return false;
}

function isBlockedAddress(ip) {
  return isPrivateIPv4(ip) || isPrivateIPv6(ip);
}

function getAllowedHosts() {
  if (!process.env.PROXY_ALLOWLIST) return null;

  return process.env.PROXY_ALLOWLIST
    .split(",")
    .map(x => x.trim().toLowerCase())
    .filter(Boolean);
}

async function validateDestination(targetUrl) {
  let url;

  try {
    url = new URL(targetUrl);
  } catch {
    throw new Error("Invalid destination URL.");
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only HTTP and HTTPS URLs are supported.");
  }

  const hostname = url.hostname.toLowerCase();

  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname === "0.0.0.0"
  ) {
    throw new Error("Local destinations are blocked.");
  }

  const allowlist = getAllowedHosts();

  if (allowlist && allowlist.length > 0) {
    const allowed = allowlist.some(host => {
      return hostname === host || hostname.endsWith(`.${host}`);
    });

    if (!allowed) {
      throw new Error("Destination is not on the proxy allowlist.");
    }
  }

  const addresses = await dnsPromises.lookup(hostname, {
    all: true,
    verbatim: false
  });

  if (!addresses.length) {
    throw new Error("Destination hostname did not resolve.");
  }

  for (const address of addresses) {
    if (isBlockedAddress(address.address)) {
      throw new Error(
        "Destination resolves to a private or local IP address."
      );
    }
  }

  return url;
}

/* -------------------------------------------------------
   Session handling
------------------------------------------------------- */

function createProxySession() {
  const id = makeId();

  sessions.set(id, {
    createdAt: Date.now(),
    cookies: new Map()
  });

  return id;
}

function getSession(req, res) {
  let id = req.cookies?.proxy_session;

  if (!id || !sessions.has(id)) {
    id = createProxySession();

    res.cookie("proxy_session", id, {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      maxAge: 24 * 60 * 60 * 1000
    });
  }

  return sessions.get(id);
}

function buildCookieHeader(session) {
  return [...session.cookies.entries()]
    .map(([name, value]) => `${name}=${value}`)
    .join("; ");
}

function storeSetCookie(session, setCookieHeaders) {
  if (!setCookieHeaders) return;

  for (const line of setCookieHeaders) {
    const firstPart = line.split(";")[0];
    const index = firstPart.indexOf("=");

    if (index === -1) continue;

    const name = firstPart.slice(0, index).trim();
    const value = firstPart.slice(index + 1).trim();

    if (!name) continue;

    session.cookies.set(name, value);
  }
}

/* -------------------------------------------------------
   Cookie parser middleware
------------------------------------------------------- */

app.use((req, _res, next) => {
  const header = req.headers.cookie || "";
  const cookies = {};

  for (const item of header.split(";")) {
    const index = item.indexOf("=");

    if (index === -1) continue;

    const name = item.slice(0, index).trim();
    const value = item.slice(index + 1).trim();

    if (name) {
      cookies[name] = decodeURIComponent(value);
    }
  }

  req.cookies = cookies;

  next();
});

/* -------------------------------------------------------
   Homepage
------------------------------------------------------- */

app.get("/", (_req, res) => {
  res.redirect("/browser");
});

/* -------------------------------------------------------
   Browser start page
------------------------------------------------------- */

app.get("/browser", (_req, res) => {
  res.setHeader("Content-Type", "text/html; charset=utf-8");

  res.send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">

<title>Web Gateway</title>

<style>
* {
  box-sizing: border-box;
}

html,
body {
  margin: 0;
  width: 100%;
  height: 100%;
  font-family: Arial, Helvetica, sans-serif;
  background: #f4f4f5;
}

body {
  display: flex;
  flex-direction: column;
}

.topbar {
  height: 64px;
  background: #111827;
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 16px;
}

.logo {
  color: white;
  font-size: 20px;
  font-weight: 700;
  white-space: nowrap;
}

.search {
  flex: 1;
  display: flex;
  gap: 8px;
}

.search input {
  width: 100%;
  height: 42px;
  border: 0;
  border-radius: 8px;
  padding: 0 14px;
  font-size: 15px;
  outline: none;
}

.search button {
  border: 0;
  background: #f97316;
  color: white;
  padding: 0 18px;
  border-radius: 8px;
  font-weight: 700;
  cursor: pointer;
}

.search button:hover {
  background: #ea580c;
}

.home {
  height: calc(100vh - 64px);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 30px;
}

.card {
  width: min(760px, 100%);
  text-align: center;
}

.ddg {
  font-size: 48px;
  font-weight: 800;
  color: #111827;
  margin-bottom: 10px;
}

.subtitle {
  color: #6b7280;
  margin-bottom: 28px;
}

.bigsearch {
  display: flex;
  gap: 10px;
}

.bigsearch input {
  flex: 1;
  height: 52px;
  border: 1px solid #d1d5db;
  border-radius: 12px;
  padding: 0 18px;
  font-size: 17px;
  outline: none;
}

.bigsearch input:focus {
  border-color: #f97316;
}

.bigsearch button {
  border: 0;
  border-radius: 12px;
  padding: 0 24px;
  background: #f97316;
  color: white;
  font-size: 16px;
  font-weight: 700;
  cursor: pointer;
}

.hint {
  margin-top: 18px;
  color: #9ca3af;
  font-size: 13px;
}

#frame {
  display: none;
  width: 100%;
  height: calc(100vh - 64px);
  border: 0;
  background: white;
}
</style>
</head>

<body>

<div class="topbar">

  <div class="logo">
    Web Gateway
  </div>

  <form class="search" id="topSearch">
    <input
      id="topInput"
      placeholder="Search DuckDuckGo or enter a URL..."
      autocomplete="off"
    >
    <button type="submit">Go</button>
  </form>

</div>

<div class="home" id="home">

  <div class="card">

    <div class="ddg">
      DuckDuckGo
    </div>

    <div class="subtitle">
      Private search through your VPS web gateway
    </div>

    <form class="bigsearch" id="mainSearch">

      <input
        id="mainInput"
        placeholder="Search the web or enter a website..."
        autocomplete="off"
        autofocus
      >

      <button type="submit">
        Search
      </button>

    </form>

    <div class="hint">
      Try: wikipedia.org &nbsp; • &nbsp; example.com &nbsp; • &nbsp; your search
    </div>

  </div>

</div>

<iframe
  id="frame"
  sandbox="allow-forms allow-modals allow-popups allow-presentation allow-same-origin allow-scripts"
></iframe>

<script>

function makeDestination(value) {

  value = value.trim();

  if (!value) return null;

  if (/^https?:\\/\\//i.test(value)) {
    return value;
  }

  if (/^[a-z0-9.-]+\\.[a-z]{2,}(\\/.*)?$/i.test(value)) {
    return "https://" + value;
  }

  return "https://duckduckgo.com/?q="
    + encodeURIComponent(value)
    + "&kl=se-sv";
}

function openDestination(value) {

  const destination = makeDestination(value);

  if (!destination) return;

  const frame = document.getElementById("frame");
  const home = document.getElementById("home");

  home.style.display = "none";
  frame.style.display = "block";

  frame.src =
    "/proxy?url="
    + encodeURIComponent(destination);
}

function submitSearch(inputId) {

  const input = document.getElementById(inputId);

  openDestination(input.value);
}

document
  .getElementById("mainSearch")
  .addEventListener("submit", function(event) {

    event.preventDefault();
    submitSearch("mainInput");

  });

document
  .getElementById("topSearch")
  .addEventListener("submit", function(event) {

    event.preventDefault();

    const value =
      document.getElementById("topInput").value;

    document.getElementById("mainInput").value = value;

    openDestination(value);

  });

</script>

</body>
</html>`);
});

/* -------------------------------------------------------
   Login/session test
------------------------------------------------------- */

app.get("/login", (req, res) => {
  const sessionId =
    req.cookies.proxy_test_session || makeId();

  res.cookie("proxy_test_session", sessionId, {
    httpOnly: true,
    sameSite: "lax",
    secure: false,
    maxAge: 60 * 60 * 1000
  });

  res.send(`
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Session Test</title>
</head>

<body style="font-family:Arial;padding:40px">

<h1>Session test</h1>

<p>Your test session is active.</p>

<p>
<a href="/session">Check session</a>
</p>

<p>
<a href="/browser">Open browser</a>
</p>

</body>
</html>
`);
});

app.get("/session", (req, res) => {
  res.json({
    authenticated: Boolean(req.cookies.proxy_test_session),
    session: req.cookies.proxy_test_session || null
  });
});

app.get("/api/session", (req, res) => {
  res.json({
    ok: true,
    authenticated: Boolean(req.cookies.proxy_test_session)
  });
});

/* -------------------------------------------------------
   Proxy
------------------------------------------------------- */

app.all("/proxy", requireProxyKey, async (req, res) => {

  const rawUrl = req.query.url;

  if (!rawUrl) {
    return res.status(400).json({
      error: "Missing URL",
      example: "/proxy?url=https://example.com"
    });
  }

  let destination;

  try {
    destination = await validateDestination(rawUrl);
  } catch (error) {
    return res.status(400).json({
      error: "Invalid destination",
      message: error.message
    });
  }

  const session = getSession(req, res);

  const controller = new AbortController();

  const timeout = setTimeout(() => {
    controller.abort();
  }, 30000);

  try {

    const headers = {
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131 Safari/537.36",

      "Accept":
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",

      "Accept-Language":
        "sv-SE,sv;q=0.9,en-US;q=0.8,en;q=0.7"
    };

    const cookieHeader = buildCookieHeader(session);

    if (cookieHeader) {
      headers.Cookie = cookieHeader;
    }

    const contentType =
      req.headers["content-type"];

    if (contentType) {
      headers["Content-Type"] = contentType;
    }

    const options = {
      method: req.method,
      headers,
      redirect: "manual",
      signal: controller.signal
    };

    if (
      !["GET", "HEAD"].includes(req.method)
    ) {

      if (
        typeof req.body === "string" ||
        Buffer.isBuffer(req.body)
      ) {

        options.body = req.body;

      } else if (
        contentType?.includes("application/json")
      ) {

        options.body =
          JSON.stringify(req.body || {});

      } else if (
        contentType?.includes(
          "application/x-www-form-urlencoded"
        )
      ) {

        options.body =
          new URLSearchParams(req.body || {})
            .toString();
      }
    }

    console.log("");
    console.log("=================================");
    console.log("[PROXY REQUEST]");
    console.log("Method:", req.method);
    console.log("URL:", destination.href);
    console.log("=================================");

    const response =
      await fetch(destination, options);

    clearTimeout(timeout);

    console.log("[PROXY RESPONSE]");
    console.log("Status:", response.status);
    console.log(
      "Content-Type:",
      response.headers.get("content-type")
    );
    console.log(
      "Server:",
      response.headers.get("server")
    );
    console.log(
      "Location:",
      response.headers.get("location")
    );

    /* -----------------------------------------------
       Upstream cookies
    ------------------------------------------------ */

    let setCookies = [];

    if (
      typeof response.headers.getSetCookie === "function"
    ) {
      setCookies =
        response.headers.getSetCookie();
    } else {

      const single =
        response.headers.get("set-cookie");

      if (single) {
        setCookies = [single];
      }
    }

    storeSetCookie(session, setCookies);

    /* -----------------------------------------------
       Redirect
    ------------------------------------------------ */

    if (
      response.status >= 300 &&
      response.status < 400
    ) {

      const location =
        response.headers.get("location");

      if (location) {

        const redirected =
          new URL(location, destination);

        const safeRedirect =
          await validateDestination(
            redirected.href
          );

        const proxyUrl =
          "/proxy?url=" +
          encodeURIComponent(
            safeRedirect.href
          );

        return res.redirect(
          response.status,
          proxyUrl
        );
      }
    }

    /* -----------------------------------------------
       Headers
    ------------------------------------------------ */

    const responseType =
      response.headers.get("content-type") || "";

    const responseEncoding =
      response.headers.get("content-encoding");

    const headersToSkip = new Set([
      "content-length",
      "content-encoding",
      "transfer-encoding",
      "connection",
      "keep-alive",
      "x-frame-options",
      "content-security-policy"
    ]);

    for (const [key, value] of response.headers) {

      if (
        headersToSkip.has(key.toLowerCase())
      ) {
        continue;
      }

      if (
        key.toLowerCase() === "set-cookie"
      ) {
        continue;
      }

      res.setHeader(key, value);
    }

    /*
      fetch() may automatically decode compressed
      responses. Therefore content-encoding is removed.
    */

    if (responseEncoding) {
      res.removeHeader("content-encoding");
    }

    /* -----------------------------------------------
       HTML
    ------------------------------------------------ */

    if (
      responseType.includes("text/html") ||
      responseType.includes("application/xhtml+xml")
    ) {

      let html =
        await response.text();

      html = rewriteHtml(
        html,
        destination.href
      );

      return res
        .status(response.status)
        .type("html")
        .send(html);
    }

    /* -----------------------------------------------
       Other content
    ------------------------------------------------ */

    const buffer =
      Buffer.from(
        await response.arrayBuffer()
      );

    return res
      .status(response.status)
      .send(buffer);

  } catch (error) {

    clearTimeout(timeout);

    console.error("");
    console.error("==============================");
    console.error("[PROXY ERROR]");
    console.error("Message:", error?.message);
    console.error("Name:", error?.name);
    console.error("Cause:", error?.cause);
    console.error("==============================");

    return res.status(502).json({

      error: "Bad gateway",

      message:
        error?.message ||
        "Unable to contact destination.",

      cause: error?.cause
        ? {
            code: error.cause.code,
            errno: error.cause.errno,
            syscall: error.cause.syscall,
            hostname: error.cause.hostname
          }
        : null
    });
  }
});

/* -------------------------------------------------------
   HTML rewriting
------------------------------------------------------- */

function rewriteHtml(html, baseUrl) {

  const base = new URL(baseUrl);

  /*
    Remove CSP meta tags because they can prevent
    the proxied page from loading its resources.
  */

  html = html.replace(
    /<meta[^>]+http-equiv=["']?Content-Security-Policy["']?[^>]*>/gi,
    ""
  );

  /*
    Remove base tags because they can make rewritten
    relative URLs resolve against the original site.
  */

  html = html.replace(
    /<base[^>]*>/gi,
    ""
  );

  /*
    Rewrite normal URL attributes.
  */

  html = html.replace(
    /\b(href|src|action)=("([^"]*)"|'([^']*)')/gi,
    (match, attribute, wrapper, doubleValue, singleValue) => {

      const value =
        doubleValue ?? singleValue ?? "";

      const rewritten =
        rewriteResourceUrl(
          value,
          base
        );

      if (!rewritten) {
        return match;
      }

      return `${attribute}="${escapeHtml(rewritten)}"`;
    }
  );

  /*
    Rewrite srcset.
  */

  html = html.replace(
    /\bsrcset=("([^"]*)"|'([^']*)')/gi,
    (match, wrapper, doubleValue, singleValue) => {

      const value =
        doubleValue ?? singleValue ?? "";

      const rewritten =
        value
          .split(",")
          .map(part => {

            const pieces =
              part.trim().split(/\s+/);

            if (!pieces[0]) {
              return part;
            }

            const newUrl =
              rewriteResourceUrl(
                pieces[0],
                base
              );

            if (!newUrl) {
              return part;
            }

            pieces[0] = newUrl;

            return pieces.join(" ");
          })
          .join(", ");

      return `srcset="${escapeHtml(rewritten)}"`;
    }
  );

  /*
    Insert a small helper so navigation from ordinary
    links stays inside the proxy.
  */

  const helper = `
<script>
(function () {

  function proxyNavigation(event) {

    const link =
      event.target.closest("a");

    if (!link) return;

    const href =
      link.getAttribute("href");

    if (!href) return;

    if (
      href.startsWith("#") ||
      href.startsWith("javascript:") ||
      href.startsWith("mailto:")
    ) {
      return;
    }

    try {

      const absolute =
        new URL(
          href,
          document.baseURI
        ).href;

      if (
        absolute.startsWith("http://") ||
        absolute.startsWith("https://")
      ) {

        event.preventDefault();

        window.location.href =
          "/proxy?url=" +
          encodeURIComponent(absolute);
      }

    } catch (_) {}

  }

  document.addEventListener(
    "click",
    proxyNavigation,
    true
  );

})();
</script>
`;

  if (/<\/body>/i.test(html)) {

    html = html.replace(
      /<\/body>/i,
      helper + "</body>"
    );

  } else {

    html += helper;
  }

  return html;
}

function rewriteResourceUrl(value, base) {

  if (!value) return null;

  const trimmed =
    value.trim();

  if (
    trimmed.startsWith("#") ||
    trimmed.startsWith("data:") ||
    trimmed.startsWith("blob:") ||
    trimmed.startsWith("javascript:") ||
    trimmed.startsWith("mailto:") ||
    trimmed.startsWith("tel:")
  ) {
    return null;
  }

  try {

    const absolute =
      new URL(trimmed, base);

    if (
      absolute.protocol !== "http:" &&
      absolute.protocol !== "https:"
    ) {
      return null;
    }

    return (
      "/proxy?url=" +
      encodeURIComponent(
        absolute.href
      )
    );

  } catch {

    return null;
  }
}

/* -------------------------------------------------------
   Health
------------------------------------------------------- */

app.get("/health", (_req, res) => {

  res.json({
    ok: true,
    service: "xcloud-test-proxy",
    time: new Date().toISOString(),
    node: process.version
  });

});

/* -------------------------------------------------------
   WebSocket test
------------------------------------------------------- */

server.on("upgrade", (request, socket, head) => {

  const url =
    new URL(
      request.url,
      `http://${request.headers.host}`
    );

  if (url.pathname !== "/stream") {

    socket.destroy();
    return;
  }

  wss.handleUpgrade(
    request,
    socket,
    head,
    ws => {

      wss.emit(
        "connection",
        ws,
        request
      );

    }
  );
});

wss.on("connection", ws => {

  let packets = 0;

  const interval =
    setInterval(() => {

      if (ws.readyState !== ws.OPEN) {
        clearInterval(interval);
        return;
      }

      packets++;

      ws.send(
        JSON.stringify({
          type: "packet",
          number: packets,
          timestamp: Date.now(),
          payload: "VPS stream test"
        })
      );

      if (packets >= 30) {

        clearInterval(interval);

        ws.send(
          JSON.stringify({
            type: "complete"
          })
        );

        ws.close();
      }

    }, 250);

  ws.on("close", () => {
    clearInterval(interval);
  });

});

/* -------------------------------------------------------
   Cleanup old sessions
------------------------------------------------------- */

setInterval(() => {

  const now = Date.now();

  for (const [id, session] of sessions) {

    if (
      now - session.createdAt >
      24 * 60 * 60 * 1000
    ) {
      sessions.delete(id);
    }

  }

}, 60 * 60 * 1000);

/* -------------------------------------------------------
   Start
------------------------------------------------------- */

server.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log("");
    console.log("=================================");
    console.log("XCloud Test Proxy");
    console.log("=================================");
    console.log(`Port: ${PORT}`);
    console.log(`Node: ${process.version}`);
    console.log(
      `Proxy key: ${PROXY_KEY ? "enabled" : "disabled"}`
    );
    console.log(
      `Allowlist: ${
        process.env.PROXY_ALLOWLIST
          ? "enabled"
          : "disabled"
      }`
    );
    console.log("");
    console.log(
      `Browser: http://0.0.0.0:${PORT}/browser`
    );
    console.log(
      `Health:  http://0.0.0.0:${PORT}/health`
    );
    console.log("=================================");

  }
);
