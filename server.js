import express from "express";
import http from "http";
import crypto from "crypto";
import { WebSocketServer } from "ws";

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 10000;

app.use(express.json());

// ============================================================
// HELPERS
// ============================================================

function makeSessionId() {
  return crypto.randomBytes(16).toString("hex");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

/*
 * Basic destination safety.
 *
 * This prevents the proxy from being used to access
 * localhost and common private network destinations.
 */
function isAllowedUrl(value) {
  try {
    const url = new URL(value);

    if (
      url.protocol !== "http:" &&
      url.protocol !== "https:"
    ) {
      return false;
    }

    const host = url.hostname.toLowerCase();

    // Localhost
    if (
      host === "localhost" ||
      host === "127.0.0.1" ||
      host === "::1" ||
      host.endsWith(".localhost") ||
      host.endsWith(".local")
    ) {
      return false;
    }

    // 10.0.0.0/8
    if (host.startsWith("10.")) {
      return false;
    }

    // 192.168.0.0/16
    if (host.startsWith("192.168.")) {
      return false;
    }

    // 172.16.0.0/12
    if (host.startsWith("172.")) {
      const parts = host.split(".");
      const second = Number(parts[1]);

      if (second >= 16 && second <= 31) {
        return false;
      }
    }

    return true;
  } catch {
    return false;
  }
}

// ============================================================
// HOME
// ============================================================

app.get("/", (req, res) => {
  res.redirect("/browser");
});

// ============================================================
// LOGIN
// ============================================================

app.get("/login", (req, res) => {
  const sessionId = makeSessionId();

  res.cookie("test_session", sessionId, {
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

  <meta
    name="viewport"
    content="width=device-width, initial-scale=1"
  >

  <title>VPS Proxy Login</title>
</head>

<body>

  <h1>VPS Proxy</h1>

  <p>Session cookie created.</p>

  <p>
    <a href="/browser">
      Open Proxy
    </a>
  </p>

  <p>
    <a href="/session">
      Test Session
    </a>
  </p>

</body>

</html>
  `);
});

// ============================================================
// SESSION TEST
// ============================================================

app.get("/session", (req, res) => {
  const session = req.headers.cookie || "";

  if (!session.includes("test_session=")) {
    return res.status(401).send(`
<!doctype html>

<html>

<head>
  <meta charset="utf-8">
  <title>Session Error</title>
</head>

<body>

<h1>401</h1>

<p>
No session cookie found.
</p>

<p>
<a href="/login">
Create session
</a>
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
  content="width=device-width, initial-scale=1"
>

<title>Session Test</title>

</head>

<body>

<h1>Session Test</h1>

<p>
Session cookie found.
</p>

<p id="api">
Testing API...
</p>

<p id="socket">
Connecting WebSocket...
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

const protocol =
  location.protocol === "https:"
    ? "wss:"
    : "ws:";

const socket =
  new WebSocket(
    protocol +
    "//" +
    location.host +
    "/stream"
  );

socket.onopen = () => {

  document.getElementById("socket")
    .textContent =
    "WebSocket: connected";

  socket.send(
    JSON.stringify({
      type: "start-stream"
    })
  );

};

socket.onmessage = event => {

  console.log(
    "WebSocket:",
    event.data
  );

};

socket.onerror = () => {

  document.getElementById("socket")
    .textContent =
    "WebSocket: error";

};

socket.onclose = () => {

  document.getElementById("socket")
    .textContent =
    "WebSocket: closed";

};

</script>

</body>

</html>
  `);
});

// ============================================================
// API
// ============================================================

app.get("/api/session", (req, res) => {
  const cookies = req.headers.cookie || "";

  if (!cookies.includes("test_session=")) {
    return res.status(401).json({
      ok: false,
      error: "No session cookie"
    });
  }

  res.json({
    ok: true,
    authenticated: true,
    message: "Session cookie successfully received"
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
  content="width=device-width, initial-scale=1"
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

  width:
    min(700px, 95vw);

  display: flex;

  gap: 10px;

}

.search input {

  flex: 1;

  padding:
    16px
    20px;

  border:
    1px solid
    #d0d0d0;

  border-radius:
    30px;

  font-size:
    16px;

  outline: none;

  box-shadow:
    0 2px 8px
    rgba(0,0,0,.08);

}

.search input:focus {

  border-color:
    #4285f4;

}

.search button {

  border: 0;

  border-radius:
    25px;

  padding:
    0 25px;

  background:
    #4285f4;

  color:
    white;

  font-size:
    15px;

  cursor:
    pointer;

}

.search button:hover {

  background:
    #3367d6;

}

.info {

  margin-top:
    20px;

  color:
    #777;

  font-size:
    13px;

}

.toolbar {

  display:
    none;

  gap:
    8px;

  padding:
    10px;

  background:
    #202124;

}

.toolbar button {

  border:
    0;

  border-radius:
    5px;

  padding:
    9px 12px;

  background:
    #3c4043;

  color:
    white;

  cursor:
    pointer;

}

.toolbar button:hover {

  background:
    #5f6368;

}

.address {

  flex:
    1;

  min-width:
    0;

  padding:
    9px 12px;

  border:
    0;

  border-radius:
    5px;

  outline:
    none;

}

.frame {

  display:
    none;

  flex:
    1;

  width:
    100%;

  border:
    0;

  background:
    white;

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

    <button onclick="goBack()">
      ←
    </button>

    <button onclick="goForward()">
      →
    </button>

    <button onclick="reloadPage()">
      ⟳
    </button>

    <button onclick="goHome()">
      ⌂
    </button>

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

  value =
    value.trim();

  if (!value) {
    return null;
  }

  if (
    !/^https?:\\/\\//i.test(value)
  ) {

    value =
      "https://" +
      value;

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
    normalizeUrl(
      homeUrl.value
    );

  if (!url) {

    alert(
      "Ogiltig URL"
    );

    return;

  }

  openPage(
    url,
    true
  );

}

function openPage(
  url,
  saveHistory
) {

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

  home.style.display =
    "none";

  toolbar.style.display =
    "flex";

  frame.style.display =
    "block";

  address.value =
    url;

  frame.src =
    "/proxy?url=" +
    encodeURIComponent(url);

}

function navigate() {

  const url =
    normalizeUrl(
      address.value
    );

  if (!url) {

    alert(
      "Ogiltig URL"
    );

    return;

  }

  openPage(
    url,
    true
  );

}

function goBack() {

  if (
    historyPosition <= 0
  ) {
    return;
  }

  historyPosition--;

  openPage(
    historyList[
      historyPosition
    ],
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
    historyList[
      historyPosition
    ],
    false
  );

}

function reloadPage() {

  try {

    frame.contentWindow
      .location
      .reload();

  } catch {

    frame.src =
      frame.src;

  }

}

function goHome() {

  frame.style.display =
    "none";

  toolbar.style.display =
    "none";

  home.style.display =
    "flex";

  homeUrl.focus();

}

address.addEventListener(
  "keydown",
  event => {

    if (
      event.key === "Enter"
    ) {

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
  // CHECK URL
  // ----------------------------------------------------------

  if (
    typeof target !== "string" ||
    !target
  ) {

    return res.status(400).send(`
<!doctype html>

<html>

<head>

<meta charset="utf-8">

<title>Proxy Error</title>

</head>

<body>

<h1>400 - Missing URL</h1>

<p>
The proxy did not receive a URL.
</p>

</body>

</html>
    `);

  }

  // ----------------------------------------------------------
  // SAFETY CHECK
  // ----------------------------------------------------------

  if (!isAllowedUrl(target)) {

    return res.status(403).send(`
<!doctype html>

<html>

<head>

<meta charset="utf-8">

<title>Proxy Error</title>

</head>

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

    targetUrl =
      new URL(target);

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
  // FETCH TARGET
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

    const headers = {

      "User-Agent":
        "School-VPS-Proxy/1.0",

      "Accept":
        req.headers.accept ||
        "*/*",

      "Accept-Language":
        req.headers[
          "accept-language"
        ] ||
        "sv-SE,sv;q=0.9,en;q=0.8"

    };

    const response =
      await fetch(
        targetUrl.href,
        {
          method:
            req.method,

          headers,

          redirect:
            "manual"
        }
      );

    // --------------------------------------------------------
    // RESPONSE INFORMATION
    // --------------------------------------------------------

    const status =
      response.status;

    const statusText =
      response.statusText ||
      "";

    const contentType =
      response.headers.get(
        "content-type"
      ) ||
      "unknown";

    const serverHeader =
      response.headers.get(
        "server"
      ) ||
      "unknown";

    const locationHeader =
      response.headers.get(
        "location"
      ) ||
      null;

    const retryAfter =
      response.headers.get(
        "retry-after"
      ) ||
      null;

    const poweredBy =
      response.headers.get(
        "x-powered-by"
      ) ||
      null;

    const cacheStatus =
      response.headers.get(
        "cf-cache-status"
      ) ||
      response.headers.get(
        "x-cache"
      ) ||
      null;

    const requestId =
      response.headers.get(
        "x-request-id"
      ) ||
      response.headers.get(
        "cf-ray"
      ) ||
      null;

    console.log(
      "STATUS:",
      status
    );

    console.log(
      "STATUS TEXT:",
      statusText
    );

    console.log(
      "CONTENT TYPE:",
      contentType
    );

    console.log(
      "SERVER:",
      serverHeader
    );

    if (locationHeader) {
      console.log(
        "LOCATION:",
        locationHeader
      );
    }

    if (retryAfter) {
      console.log(
        "RETRY-AFTER:",
        retryAfter
      );
    }

    if (poweredBy) {
      console.log(
        "X-POWERED-BY:",
        poweredBy
      );
    }

    if (cacheStatus) {
      console.log(
        "CACHE STATUS:",
        cacheStatus
      );
    }

    if (requestId) {
      console.log(
        "REQUEST ID:",
        requestId
      );
    }

    console.log(
      "========================================"
    );

    // --------------------------------------------------------
    // READ RESPONSE
    // --------------------------------------------------------

    const data =
      Buffer.from(
        await response.arrayBuffer()
      );

    // --------------------------------------------------------
    // REDIRECT
    // --------------------------------------------------------

    if (
      status >= 300 &&
      status < 400
    ) {

      if (locationHeader) {

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
The destination returned an invalid redirect.
</p>

</body>

</html>
          `);

        }

        if (
          !isAllowedUrl(
            nextUrl
          )
        ) {

          return res.status(403).send(`
<!doctype html>

<html>

<body>

<h1>403 - Redirect blocked</h1>

<p>
The destination attempted to redirect
to a blocked address.
</p>

</body>

</html>
          `);

        }

        return res.redirect(
          "/proxy?url=" +
          encodeURIComponent(
            nextUrl
          )
        );

      }

    }

    // --------------------------------------------------------
    // ERROR RESPONSE
    // --------------------------------------------------------

    if (status >= 400) {

      const rawText =
        data.toString(
          "utf8"
        );

      // Remove scripts/styles before
      // creating a readable preview.

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
          .slice(
            0,
            2000
          );

      let diagnosis =
        "Unknown error.";

      if (status === 400) {

        diagnosis =
          "Bad Request: målservern anser att begäran är felaktig.";

      } else if (status === 401) {

        diagnosis =
          "Unauthorized: målservern kräver autentisering.";

      } else if (status === 403) {

        diagnosis =
          "Forbidden: målservern har tagit emot begäran men nekar åtkomst.";

      } else if (status === 404) {

        diagnosis =
          "Not Found: den begärda resursen hittades inte.";

      } else if (status === 408) {

        diagnosis =
          "Request Timeout: målservern väntade för länge.";

      } else if (status === 409) {

        diagnosis =
          "Conflict: begäran krockar med målserverns aktuella tillstånd.";

      } else if (status === 429) {

        diagnosis =
          "Too Many Requests: målservern begränsar antalet begäranden.";

      } else if (status >= 500) {

        diagnosis =
          "Server Error: målservern rapporterar ett serverfel.";

      }

      return res
        .status(status)
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

  background:
    #111827;

  color:
    #e5e7eb;

  font-family:
    Arial,
    sans-serif;

}

.container {

  max-width:
    900px;

  margin:
    auto;

}

.card {

  background:
    #1f2937;

  border-radius:
    12px;

  padding:
    25px;

  margin-bottom:
    15px;

}

.status {

  font-size:
    42px;

  font-weight:
    bold;

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

  color:
    #9ca3af;

  font-size:
    13px;

  margin-bottom:
    5px;

}

.value {

  word-break:
    break-all;

}

.preview {

  white-space:
    pre-wrap;

  word-break:
    break-word;

  max-height:
    350px;

  overflow:
    auto;

  background:
    #030712;

  padding:
    15px;

  border-radius:
    6px;

}

code {

  word-break:
    break-all;

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
${escapeHtml(
  diagnosis
)}
</p>

</div>

<div class="card">

<div class="label">
URL
</div>

<div class="value">
${escapeHtml(
  targetUrl.href
)}
</div>

</div>

<div class="card">

<div class="label">
Content-Type
</div>

<div class="value">
${escapeHtml(
  contentType
)}
</div>

</div>

<div class="card">

<div class="label">
Server
</div>

<div class="value">
${escapeHtml(
  serverHeader
)}
</div>

</div>

${
  locationHeader
    ? `
<div class="card">
<div class="label">
Location
</div>
<div class="value">
${escapeHtml(
  locationHeader
)}
</div>
</div>
`
    : ""
}

${
  retryAfter
    ? `
<div class="card">
<div class="label">
Retry-After
</div>
<div class="value">
${escapeHtml(
  retryAfter
)}
</div>
</div>
`
    : ""
}

${
  poweredBy
    ? `
<div class="card">
<div class="label">
X-Powered-By
</div>
<div class="value">
${escapeHtml(
  poweredBy
)}
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
Cache / CDN status
</div>
<div class="value">
${escapeHtml(
  cacheStatus
)}
</div>
</div>
`
    : ""
}

${
  requestId
    ? `
<div class="card">
<div class="label">
Request / CDN ID
</div>
<div class="value">
${escapeHtml(
  requestId
)}
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
  "Målservern skickade ingen läsbar response body."
)}
</div>

</div>

</div>

</body>

</html>
        `);

    }

    // --------------------------------------------------------
    // NORMAL HTML RESPONSE
    // --------------------------------------------------------

    if (
      contentType.includes(
        "text/html"
      )
    ) {

      let html =
        data.toString(
          "utf8"
        );

      // Remove CSP meta tags from
      // the returned document.

      html =
        html.replace(
          /<meta[^>]+http-equiv=["']Content-Security-Policy["'][^>]*>/gi,
          ""
        );

      // Rewrite normal href/src/action
      // links so they go through /proxy.

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
              value.startsWith("mailto:")
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
                !absolute.startsWith(
                  "http://"
                ) &&
                !absolute.startsWith(
                  "https://"
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

      // Rewrite srcset images.

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

                  if (
                    !parts[0]
                  ) {
                    return item;
                  }

                  try {

                    const absolute =
                      new URL(
                        parts[0],
                        targetUrl.href
                      ).href;

                    parts[0] =
                      "/proxy?url=" +
                      encodeURIComponent(
                        absolute
                      );

                    return parts.join(
                      " "
                    );

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

      res.status(status);

      res.set(
        "Content-Type",
        "text/html; charset=utf-8"
      );

      return res.send(html);
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

    return res.status(502).send(`
<!doctype html>

<html>

<head>

<meta charset="utf-8">

<title>Proxy Internal Error</title>

</head>

<body>

<h1>
502 - Proxy Internal Error
</h1>

<p>
Proxyservern kunde inte slutföra begäran.
</p>

<h3>Error</h3>

<pre>
${escapeHtml(
  error.stack ||
  error.message ||
  String(error)
)}
</pre>

</body>

</html>
    `);
  }

});

// ============================================================
// WEBSOCKET STREAM
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
      "Streaming client connected"
    );

    socket.send(
      JSON.stringify({
        type:
          "connected",

        message:
          "Streaming session established"
      })
    );

    let packetNumber = 0;

    const interval =
      setInterval(
        () => {

          if (
            socket.readyState !== 1
          ) {

            clearInterval(
              interval
            );

            return;
          }

          packetNumber++;

          const packet =
            Buffer.alloc(
              1024
            );

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
              (
                packetNumber +
                i
              ) % 256;

          }

          socket.send(
            packet
          );

          if (
            packetNumber >= 30
          ) {

            clearInterval(
              interval
            );

            socket.send(
              JSON.stringify({
                type:
                  "stream-complete"
              })
            );

          }

        },
        250
      );

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

        clearInterval(
          interval
        );

        console.log(
          "Streaming client disconnected"
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

      ok:
        true,

      http:
        true,

      websocket:
        true,

      streaming:
        true,

      browser:
        true,

      proxy:
        true

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
      "Browser: /browser"
    );

    console.log(
      "Proxy: /proxy?url=https://example.com"
    );

    console.log(
      "Health: /health"
    );

    console.log(
      "========================================"
    );

  }
);
