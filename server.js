import express from "express";
import http from "http";
import crypto from "crypto";
import { WebSocketServer } from "ws";

const app = express();
const server = http.createServer(app);

const PORT = Number(process.env.PORT) || 10000;

app.disable("x-powered-by");

app.use(express.json({ limit: "1mb" }));

// ============================================================
// CONFIG
// ============================================================

const PROXY_USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
  "AppleWebKit/537.36 (KHTML, like Gecko) " +
  "Chrome/131.0.0.0 Safari/537.36";

const sessions = new Map();

// Keep sessions from growing forever.
setInterval(() => {
  const now = Date.now();

  for (const [id, session] of sessions) {
    if (now - session.lastUsed > 60 * 60 * 1000) {
      sessions.delete(id);
    }
  }
}, 10 * 60 * 1000);

// ============================================================
// HELPERS
// ============================================================

function makeSessionId() {
  return crypto.randomBytes(24).toString("hex");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function getSession(req) {
  const cookieHeader = req.headers.cookie || "";

  const match = cookieHeader.match(
    /(?:^|;\s*)proxy_session=([^;]+)/
  );

  if (!match) {
    return null;
  }

  const session = sessions.get(match[1]);

  if (!session) {
    return null;
  }

  session.lastUsed = Date.now();

  return session;
}

function createSession() {
  const id = makeSessionId();

  sessions.set(id, {
    cookies: new Map(),
    lastUsed: Date.now()
  });

  return id;
}

// ============================================================
// DESTINATION SAFETY
// ============================================================

function isPrivateIPv4(host) {
  const parts = host.split(".").map(Number);

  if (parts.length !== 4 || parts.some(Number.isNaN)) {
    return false;
  }

  const [a, b] = parts;

  if (a === 10) return true;

  if (a === 127) return true;

  if (a === 169 && b === 254) return true;

  if (a === 192 && b === 168) return true;

  if (a === 172 && b >= 16 && b <= 31) {
    return true;
  }

  return false;
}

function isAllowedUrl(value) {
  try {
    const url = new URL(value);

    if (
      url.protocol !== "http:" &&
      url.protocol !== "https:"
    ) {
      return false;
    }

    const host = url.hostname
      .toLowerCase()
      .replace(/^\[|\]$/g, "");

    if (
      host === "localhost" ||
      host.endsWith(".localhost") ||
      host.endsWith(".local") ||
      host === "::1"
    ) {
      return false;
    }

    if (isPrivateIPv4(host)) {
      return false;
    }

    // IPv6 loopback / private ranges.
    if (
      host === "::1" ||
      host.startsWith("fc") ||
      host.startsWith("fd") ||
      host.startsWith("fe80:")
    ) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

// ============================================================
// COOKIE HANDLING
// ============================================================

function storeSetCookies(session, setCookieHeaders) {
  if (!session || !setCookieHeaders) {
    return;
  }

  for (const header of setCookieHeaders) {
    const firstPart = header.split(";")[0];

    const index = firstPart.indexOf("=");

    if (index === -1) {
      continue;
    }

    const name = firstPart.slice(0, index).trim();
    const value = firstPart.slice(index + 1).trim();

    if (!name) {
      continue;
    }

    session.cookies.set(name, value);
  }
}

function buildCookieHeader(session) {
  if (!session || session.cookies.size === 0) {
    return undefined;
  }

  return [...session.cookies.entries()]
    .map(([name, value]) => `${name}=${value}`)
    .join("; ");
}

// ============================================================
// HOME
// ============================================================

app.get("/", (req, res) => {
  res.redirect("/browser");
});

// ============================================================
// LOGIN / SESSION
// ============================================================

app.get("/login", (req, res) => {
  const sessionId = createSession();

  res.cookie("proxy_session", sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: 60 * 60 * 1000
  });

  res.type("html").send(`
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VPS Proxy Login</title>
</head>

<body>

<h1>VPS Proxy</h1>

<p>Proxy session created.</p>

<p>
<a href="/browser">Open Proxy</a>
</p>

<p>
<a href="/session">Test Session</a>
</p>

</body>
</html>
  `);
});

app.get("/session", (req, res) => {
  const session = getSession(req);

  if (!session) {
    return res.status(401).send(`
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Session Error</title>
</head>

<body>

<h1>401</h1>

<p>No proxy session found.</p>

<p>
<a href="/login">Create session</a>
</p>

</body>
</html>
    `);
  }

  res.type("html").send(`
<!doctype html>
<html>

<head>

<meta charset="utf-8">

<meta
  name="viewport"
  content="width=device-width,initial-scale=1"
>

<title>Session Test</title>

</head>

<body>

<h1>Session Test</h1>

<p>
Proxy session is active.
</p>

<p>
Stored upstream cookies:
${session.cookies.size}
</p>

<p id="api">
Testing API...
</p>

<script>

fetch("/api/session")
  .then(async response => {

    const data =
      await response.json();

    document.getElementById("api")
      .textContent =
      "API: " +
      JSON.stringify(data);

  })
  .catch(error => {

    document.getElementById("api")
      .textContent =
      "API error: " +
      error;

  });

</script>

</body>
</html>
  `);
});

app.get("/api/session", (req, res) => {
  const session = getSession(req);

  if (!session) {
    return res.status(401).json({
      ok: false,
      error: "No proxy session"
    });
  }

  res.json({
    ok: true,
    authenticated: true,
    upstreamCookies: session.cookies.size
  });
});

// ============================================================
// BROWSER UI
// ============================================================

app.get("/browser", (req, res) => {
  res.type("html").send(`
<!doctype html>

<html>

<head>

<meta charset="utf-8">

<meta
  name="viewport"
  content="width=device-width,initial-scale=1"
>

<title>VPS Proxy</title>

<style>

* {
  box-sizing: border-box;
}

html,
body {

  margin: 0;
  padding: 0;

  width: 100%;
  height: 100%;

  font-family:
    Arial,
    Helvetica,
    sans-serif;

  background: #f5f5f5;
}

.page {

  width: 100%;
  height: 100%;

  display: flex;
  flex-direction: column;
}

.home {

  height: 100%;

  display: flex;
  flex-direction: column;

  align-items: center;
  justify-content: center;

  padding: 20px;
}

.logo {

  font-size: 58px;
  font-weight: bold;

  margin-bottom: 30px;

  letter-spacing: -3px;
}

.logo span:nth-child(1) {
  color: #4285f4;
}

.logo span:nth-child(2) {
  color: #ea4335;
}

.logo span:nth-child(3) {
  color: #fbbc05;
}

.logo span:nth-child(4) {
  color: #4285f4;
}

.logo span:nth-child(5) {
  color: #34a853;
}

.logo span:nth-child(6) {
  color: #ea4335;
}

.search {

  width: min(700px, 95vw);

  display: flex;

  gap: 10px;
}

.search input {

  flex: 1;

  padding: 16px 20px;

  border: 1px solid #d0d0d0;

  border-radius: 30px;

  font-size: 16px;

  outline: none;

  box-shadow:
    0 2px 8px rgba(0,0,0,.08);
}

.search input:focus {

  border-color: #4285f4;
}

.search button {

  border: 0;

  border-radius: 25px;

  padding: 0 25px;

  background: #4285f4;

  color: white;

  font-size: 15px;

  cursor: pointer;
}

.search button:hover {

  background: #3367d6;
}

.info {

  margin-top: 20px;

  color: #777;

  font-size: 13px;
}

.toolbar {

  display: none;

  gap: 8px;

  padding: 10px;

  background: #202124;
}

.toolbar button {

  border: 0;

  border-radius: 5px;

  padding: 9px 12px;

  background: #3c4043;

  color: white;

  cursor: pointer;
}

.toolbar button:hover {

  background: #5f6368;
}

.address {

  flex: 1;

  min-width: 0;

  padding: 9px 12px;

  border: 0;

  border-radius: 5px;

  outline: none;
}

.frame {

  display: none;

  flex: 1;

  width: 100%;

  border: 0;

  background: white;
}

</style>

</head>

<body>

<div class="page">

  <div
    class="home"
    id="home"
  >

    <div class="logo">

      <span>V</span>
      <span>P</span>
      <span>S</span>
      <span>P</span>
      <span>R</span>
      <span>O</span>

    </div>

    <form
      class="search"
      onsubmit="openFromHome(event)"
    >

      <input
        id="homeUrl"
        type="text"
        placeholder="https://example.com"
        autocomplete="off"
      >

      <button type="submit">
        Öppna
      </button>

    </form>

    <div class="info">
      Server-side web proxy
    </div>

  </div>

  <div
    class="toolbar"
    id="toolbar"
  >

    <button onclick="goBack()">←</button>

    <button onclick="goForward()">→</button>

    <button onclick="reloadPage()">⟳</button>

    <button onclick="goHome()">⌂</button>

    <input
      id="address"
      class="address"
      type="text"
      placeholder="https://example.com"
      autocomplete="off"
    >

    <button onclick="navigate()">
      Go
    </button>

  </div>

  <iframe
    id="frame"
    class="frame"
    sandbox="
      allow-forms
      allow-modals
      allow-popups
      allow-pointer-lock
      allow-presentation
      allow-same-origin
      allow-scripts
    "
  ></iframe>

</div>

<script>

const home =
  document.getElementById("home");

const toolbar =
  document.getElementById("toolbar");

const frame =
  document.getElementById("frame");

const homeUrl =
  document.getElementById("homeUrl");

const address =
  document.getElementById("address");

let historyList = [];

let historyPosition = -1;

function normalizeUrl(value) {

  value = value.trim();

  if (!value) {
    return null;
  }

  if (!/^https?:\\/\\//i.test(value)) {
    value = "https://" + value;
  }

  try {
    return new URL(value).href;
  } catch {
    return null;
  }
}

function openFromHome(event) {

  event.preventDefault();

  const url =
    normalizeUrl(homeUrl.value);

  if (!url) {
    alert("Ogiltig URL");
    return;
  }

  openPage(url, true);
}

function openPage(url, saveHistory) {

  if (!url) {
    return;
  }

  if (saveHistory) {

    historyList =
      historyList.slice(
        0,
        historyPosition + 1
      );

    historyList.push(url);

    historyPosition++;

  }

  home.style.display = "none";

  toolbar.style.display = "flex";

  frame.style.display = "block";

  address.value = url;

  frame.src =
    "/proxy?url=" +
    encodeURIComponent(url);
}

function navigate() {

  const url =
    normalizeUrl(address.value);

  if (!url) {
    alert("Ogiltig URL");
    return;
  }

  openPage(url, true);
}

function goBack() {

  if (historyPosition <= 0) {
    return;
  }

  historyPosition--;

  openPage(
    historyList[historyPosition],
    false
  );
}

function goForward() {

  if (
    historyPosition >=
    historyList.length - 1
  ) {
    return;
  }

  historyPosition++;

  openPage(
    historyList[historyPosition],
    false
  );
}

function reloadPage() {

  frame.src = frame.src;
}

function goHome() {

  frame.style.display = "none";

  toolbar.style.display = "none";

  home.style.display = "flex";

  homeUrl.focus();
}

address.addEventListener(
  "keydown",
  event => {

    if (event.key === "Enter") {
      navigate();
    }

  }
);

</script>

</body>

</html>
  `);
});

// ============================================================
// PROXY
// ============================================================

app.all("/proxy", async (req, res) => {

  const target =
    req.query.url;

  // ----------------------------------------------------------
  // VALIDATE URL
  // ----------------------------------------------------------

  if (
    typeof target !== "string" ||
    !target
  ) {
    return res.status(400).send(`
<!doctype html>
<html>
<body>

<h1>400 - Missing URL</h1>

<p>
The proxy did not receive a URL.
</p>

</body>
</html>
    `);
  }

  if (!isAllowedUrl(target)) {
    return res.status(403).send(`
<!doctype html>
<html>
<body>

<h1>403 - Destination not allowed</h1>

<p>
The requested destination is not allowed by this proxy.
</p>

</body>
</html>
    `);
  }

  let targetUrl;

  try {
    targetUrl = new URL(target);
  } catch {
    return res.status(400).send(`
<!doctype html>
<html>
<body>

<h1>400 - Invalid URL</h1>

<p>
${escapeHtml(target)}
</p>

</body>
</html>
    `);
  }

  // ----------------------------------------------------------
  // SESSION
  // ----------------------------------------------------------

  let session = getSession(req);

  if (!session) {

    const sessionId =
      createSession();

    session =
      sessions.get(sessionId);

    res.cookie(
      "proxy_session",
      sessionId,
      {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        maxAge:
          60 * 60 * 1000
      }
    );
  }

  // ----------------------------------------------------------
  // REQUEST HEADERS
  // ----------------------------------------------------------

  const headers = {

    "User-Agent":
      PROXY_USER_AGENT,

    "Accept":
      req.headers.accept ||
      "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",

    "Accept-Language":
      req.headers["accept-language"] ||
      "sv-SE,sv;q=0.9,en-US;q=0.8,en;q=0.7",

    "Cache-Control":
      req.headers["cache-control"] ||
      "no-cache"
  };

  const cookieHeader =
    buildCookieHeader(session);

  if (cookieHeader) {
    headers.Cookie = cookieHeader;
  }

  // ----------------------------------------------------------
  // BODY
  // ----------------------------------------------------------

  let body = undefined;

  if (
    req.method !== "GET" &&
    req.method !== "HEAD" &&
    req.body &&
    typeof req.body === "object"
  ) {

    const contentType =
      req.headers["content-type"] ||
      "";

    if (
      contentType.includes(
        "application/json"
      )
    ) {

      body =
        JSON.stringify(req.body);

      headers[
        "Content-Type"
      ] =
        "application/json";

    }

  }

  // ----------------------------------------------------------
  // FETCH
  // ----------------------------------------------------------

  try {

    console.log("");
    console.log(
      "========================================"
    );

    console.log(
      "PROXY REQUEST"
    );

    console.log(
      "URL:",
      targetUrl.href
    );

    console.log(
      "METHOD:",
      req.method
    );

    console.log(
      "========================================"
    );

    const response =
      await fetch(
        targetUrl.href,
        {
          method:
            req.method,

          headers,

          body,

          redirect:
            "manual",

          signal:
            AbortSignal.timeout(
              30000
            )
        }
      );

    // --------------------------------------------------------
    // RESPONSE METADATA
    // --------------------------------------------------------

    const status =
      response.status;

    const statusText =
      response.statusText || "";

    const contentType =
      response.headers.get(
        "content-type"
      ) ||
      "application/octet-stream";

    const serverHeader =
      response.headers.get(
        "server"
      ) ||
      "unknown";

    const locationHeader =
      response.headers.get(
        "location"
      );

    const requestId =
      response.headers.get(
        "cf-ray"
      ) ||
      response.headers.get(
        "x-request-id"
      );

    const cacheStatus =
      response.headers.get(
        "cf-cache-status"
      ) ||
      response.headers.get(
        "x-cache"
      );

    console.log(
      "STATUS:",
      status
    );

    console.log(
      "CONTENT TYPE:",
      contentType
    );

    console.log(
      "SERVER:",
      serverHeader
    );

    if (requestId) {
      console.log(
        "REQUEST ID:",
        requestId
      );
    }

    // --------------------------------------------------------
    // STORE UPSTREAM COOKIES
    // --------------------------------------------------------

    try {

      const setCookies =
        response.headers.getSetCookie();

      if (setCookies.length) {

        storeSetCookies(
          session,
          setCookies
        );

      }

    } catch {
      // Some environments do not expose
      // getSetCookie().
    }

    // --------------------------------------------------------
    // REDIRECT
    // --------------------------------------------------------

    if (
      status >= 300 &&
      status < 400 &&
      locationHeader
    ) {

      let nextUrl;

      try {

        nextUrl =
          new URL(
            locationHeader,
            targetUrl.href
          ).href;

      } catch {

        return res.status(502).send(`
<!doctype html>
<html>
<body>

<h1>502 - Invalid redirect</h1>

<p>
The target returned an invalid redirect.
</p>

</body>
</html>
        `);
      }

      if (!isAllowedUrl(nextUrl)) {

        return res.status(403).send(`
<!doctype html>
<html>
<body>

<h1>403 - Redirect blocked</h1>

<p>
The target attempted to redirect
to a blocked destination.
</p>

</body>
</html>
        `);
      }

      return res.redirect(
        "/proxy?url=" +
        encodeURIComponent(nextUrl)
      );
    }

    // --------------------------------------------------------
    // READ RESPONSE
    // --------------------------------------------------------

    const data =
      Buffer.from(
        await response.arrayBuffer()
      );

    // --------------------------------------------------------
    // TARGET ERROR
    // --------------------------------------------------------

    if (status >= 400) {

      const rawText =
        data.toString("utf8");

      const preview =
        rawText
          .replace(
            /<script[\s\S]*?<\/script>/gi,
            ""
          )
          .replace(
            /<style[\s\S]*?<\/style>/gi,
            ""
          )
          .replace(
            /<[^>]+>/g,
            " "
          )
          .replace(
            /\s+/g,
            " "
          )
          .trim()
          .slice(0, 2500);

      let diagnosis =
        "The target returned an error.";

      if (status === 401) {

        diagnosis =
          "The target requires authentication.";

      } else if (status === 403) {

        diagnosis =
          "The target received the request but refused access.";

      } else if (status === 404) {

        diagnosis =
          "The requested resource was not found.";

      } else if (status === 408) {

        diagnosis =
          "The target timed out.";

      } else if (status === 429) {

        diagnosis =
          "The target is rate limiting requests.";

      } else if (status >= 500) {

        diagnosis =
          "The target reported a server-side error.";
      }

      return res
        .status(status)
        .type("html")
        .send(`
<!doctype html>

<html>

<head>

<meta charset="utf-8">

<meta
  name="viewport"
  content="width=device-width,initial-scale=1"
>

<title>Proxy Diagnostic</title>

<style>

body {

  margin: 0;

  padding: 30px;

  background: #111827;

  color: #e5e7eb;

  font-family:
    Arial,
    sans-serif;
}

.container {

  max-width: 900px;

  margin: auto;
}

.card {

  background: #1f2937;

  border-radius: 12px;

  padding: 25px;

  margin-bottom: 15px;
}

.status {

  font-size: 42px;

  font-weight: bold;

  color:
    ${
      status === 403
        ? "#f59e0b"
        : status >= 500
          ? "#ef4444"
          : "#60a5fa"
    };
}

.label {

  color: #9ca3af;

  font-size: 13px;

  margin-bottom: 5px;
}

.value {

  word-break: break-all;
}

.preview {

  white-space: pre-wrap;

  word-break: break-word;

  max-height: 400px;

  overflow: auto;

  background: #030712;

  padding: 15px;

  border-radius: 6px;
}

</style>

</head>

<body>

<div class="container">

<div class="card">

<div class="status">
HTTP ${status}
</div>

<h2>
${escapeHtml(
  statusText ||
  "Target returned an error"
)}
</h2>

<p>
${escapeHtml(diagnosis)}
</p>

</div>

<div class="card">

<div class="label">
Requested URL
</div>

<div class="value">
${escapeHtml(targetUrl.href)}
</div>

</div>

<div class="card">

<div class="label">
Content-Type
</div>

<div class="value">
${escapeHtml(contentType)}
</div>

</div>

<div class="card">

<div class="label">
Server
</div>

<div class="value">
${escapeHtml(serverHeader)}
</div>

</div>

${
  requestId
    ? `
<div class="card">

<div class="label">
Request / CDN ID
</div>

<div class="value">
${escapeHtml(requestId)}
</div>

</div>
`
    : ""
}

${
  cacheStatus
    ? `
<div class="card">

<div class="label">
CDN / Cache status
</div>

<div class="value">
${escapeHtml(cacheStatus)}
</div>

</div>
`
    : ""
}

<div class="card">

<div class="label">
Response preview
</div>

<div class="preview">
${escapeHtml(
  preview ||
  "No readable response body."
)}
</div>

</div>

</div>

</body>

</html>
        `);
    }

    // --------------------------------------------------------
    // HTML
    // --------------------------------------------------------

    if (
      contentType
        .toLowerCase()
        .includes("text/html")
    ) {

      let html =
        data.toString("utf8");

      // Remove CSP meta tags.
      html =
        html.replace(
          /<meta[^>]+http-equiv=["']Content-Security-Policy["'][^>]*>/gi,
          ""
        );

      // Rewrite URLs in href/src/action.
      html =
        html.replace(
          /(\s(?:href|src|action)=["'])([^"']+)(["'])/gi,
          (
            match,
            start,
            value,
            end
          ) => {

            if (
              value.startsWith("#") ||
              value.startsWith("data:") ||
              value.startsWith("javascript:") ||
              value.startsWith("mailto:") ||
              value.startsWith("tel:")
            ) {
              return match;
            }

            try {

              const absolute =
                new URL(
                  value,
                  targetUrl.href
                ).href;

              if (
                !isAllowedUrl(
                  absolute
                )
              ) {
                return match;
              }

              return (
                start +
                "/proxy?url=" +
                encodeURIComponent(
                  absolute
                ) +
                end
              );

            } catch {

              return match;
            }
          }
        );

      // Rewrite srcset.
      html =
        html.replace(
          /(\ssrcset=["'])([^"']+)(["'])/gi,
          (
            match,
            start,
            value,
            end
          ) => {

            const rewritten =
              value
                .split(",")
                .map(item => {

                  const parts =
                    item
                      .trim()
                      .split(/\s+/);

                  if (!parts[0]) {
                    return item;
                  }

                  try {

                    const absolute =
                      new URL(
                        parts[0],
                        targetUrl.href
                      ).href;

                    if (
                      !isAllowedUrl(
                        absolute
                      )
                    ) {
                      return item;
                    }

                    parts[0] =
                      "/proxy?url=" +
                      encodeURIComponent(
                        absolute
                      );

                    return parts.join(" ");

                  } catch {

                    return item;
                  }

                })
                .join(", ");

            return (
              start +
              rewritten +
              end
            );
          }
        );

      // Rewrite <base href>.
      html =
        html.replace(
          /<base\s+href=["']([^"']+)["'][^>]*>/gi,
          (
            match,
            value
          ) => {

            try {

              const absolute =
                new URL(
                  value,
                  targetUrl.href
                ).href;

              return `
<base href="/proxy?url=${encodeURIComponent(
                absolute
              )}">
              `;

            } catch {

              return match;
            }
          }
        );

      // Do not allow the target to escape
      // the proxy with a normal top-level form.
      html =
        html.replace(
          /target=["']_top["']/gi,
          'target="_self"'
        );

      // Response headers that commonly
      // interfere with embedding.
      res.removeHeader(
        "Content-Security-Policy"
      );

      res.removeHeader(
        "X-Frame-Options"
      );

      res.removeHeader(
        "Content-Encoding"
      );

      res.set(
        "Content-Type",
        "text/html; charset=utf-8"
      );

      return res
        .status(status)
        .send(html);
    }

    // --------------------------------------------------------
    // OTHER CONTENT
    // --------------------------------------------------------

    if (contentType) {

      res.set(
        "Content-Type",
        contentType
      );
    }

    // Do not forward upstream
    // Content-Encoding because fetch()
    // may already have decoded the body.

    return res
      .status(status)
      .send(data);

  } catch (error) {

    console.error("");
    console.error(
      "========================================"
    );

    console.error(
      "PROXY INTERNAL ERROR"
    );

    console.error(
      error
    );

    console.error(
      "========================================"
    );

    const message =
      error?.name === "TimeoutError"
        ? "The target request timed out."
        : error?.message ||
          "Unknown proxy error.";

    return res
      .status(502)
      .type("html")
      .send(`
<!doctype html>

<html>

<head>

<meta charset="utf-8">

<title>Proxy Error</title>

</head>

<body>

<h1>
502 - Proxy Error
</h1>

<p>
The proxy could not complete the request.
</p>

<pre>
${escapeHtml(message)}
</pre>

</body>

</html>
      `);
  }

});

// ============================================================
// WEBSOCKET
// ============================================================

const wss =
  new WebSocketServer({
    server,
    path: "/stream"
  });

wss.on(
  "connection",
  socket => {

    console.log(
      "WebSocket client connected"
    );

    socket.send(
      JSON.stringify({
        type: "connected",
        message:
          "Streaming session established"
      })
    );

    let packetNumber = 0;

    const interval =
      setInterval(() => {

        if (
          socket.readyState !== 1
        ) {

          clearInterval(interval);

          return;
        }

        packetNumber++;

        const packet =
          Buffer.alloc(1024);

        packet.writeUInt32BE(
          packetNumber,
          0
        );

        for (
          let i = 4;
          i < packet.length;
          i++
        ) {

          packet[i] =
            (packetNumber + i) % 256;

        }

        socket.send(packet);

        if (
          packetNumber >= 30
        ) {

          clearInterval(interval);

          socket.send(
            JSON.stringify({
              type:
                "stream-complete"
            })
          );

        }

      }, 250);

    socket.on(
      "message",
      message => {

        console.log(
          "Client message:",
          message.toString()
        );

      }
    );

    socket.on(
      "close",
      () => {

        clearInterval(interval);

        console.log(
          "WebSocket client disconnected"
        );

      }
    );

  }
);

// ============================================================
// HEALTH
// ============================================================

app.get(
  "/health",
  (req, res) => {

    res.json({

      ok: true,

      http: true,

      websocket: true,

      streaming: true,

      browser: true,

      proxy: true,

      sessions: sessions.size

    });

  }
);

// ============================================================
// START
// ============================================================

server.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      "========================================"
    );

    console.log(
      "VPS PROXY STARTED"
    );

    console.log(
      "Port:",
      PORT
    );

    console.log(
      "Browser:",
      "/browser"
    );

    console.log(
      "Proxy:",
      "/proxy?url=https://example.com"
    );

    console.log(
      "Health:",
      "/health"
    );

    console.log(
      "========================================"
    );

  }
);
