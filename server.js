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

    // Block local/private destinations.
    if (
      host === "localhost" ||
      host === "127.0.0.1" ||
      host === "::1" ||
      host.endsWith(".localhost") ||
      host.endsWith(".local") ||
      host.startsWith("10.") ||
      host.startsWith("192.168.")
    ) {
      return false;
    }

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
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Proxy Login</title>
</head>

<body>

<h1>VPS Proxy</h1>

<p>Session cookie created.</p>

<p>
  <a href="/browser">Open Proxy</a>
</p>

</body>
</html>
  `);
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
  font-family: Arial, sans-serif;
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
  font-size: 52px;
  font-weight: bold;
  margin-bottom: 30px;
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
  width: min(650px, 95vw);
  display: flex;
  gap: 8px;
}

.search input {
  flex: 1;
  padding: 15px 20px;
  border: 1px solid #d0d0d0;
  border-radius: 30px;
  font-size: 16px;
  outline: none;
  box-shadow: 0 2px 8px rgba(0,0,0,.08);
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

.info {
  margin-top: 20px;
  color: #777;
  font-size: 13px;
  text-align: center;
}

</style>

</head>

<body>

<div class="page">

  <div class="home" id="home">

    <div class="logo">
      <span>V</span><span>P</span><span>S</span>
      <span> </span><span>P</span><span>R</span><span>OXY</span>
    </div>

    <form
      class="search"
      onsubmit="openFromHome(event)"
    >

      <input
        id="homeUrl"
        type="text"
        placeholder="Skriv en URL, t.ex. https://example.com"
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

  <div class="toolbar" id="toolbar">

    <button onclick="goBack()">←</button>

    <button onclick="goForward()">→</button>

    <button onclick="reloadPage()">⟳</button>

    <button onclick="home()">⌂</button>

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
    sandbox="allow-forms allow-modals allow-popups allow-pointer-lock allow-presentation allow-same-origin allow-scripts"
  ></iframe>

</div>

<script>

const homeElement =
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

  if (
    !/^https?:\\/\\//i.test(value)
  ) {
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

function openPage(url, addHistory) {

  if (!url) {
    return;
  }

  if (addHistory) {

    historyList =
      historyList.slice(
        0,
        historyPosition + 1
      );

    historyList.push(url);

    historyPosition++;

  }

  homeElement.style.display = "none";

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

  try {
    frame.contentWindow.location.reload();
  } catch {
    frame.src = frame.src;
  }

}

function home() {

  frame.style.display = "none";

  toolbar.style.display = "none";

  homeElement.style.display = "flex";

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

  const target = req.query.url;

  if (
    typeof target !== "string" ||
    !target
  ) {

    return res.status(400).send(`
      <h1>400</h1>
      <p>Missing URL.</p>
    `);

  }

  if (!isAllowedUrl(target)) {

    return res.status(403).send(`
      <h1>403</h1>
      <p>Destination is not allowed.</p>
    `);

  }

  try {

    const targetUrl =
      new URL(target);

    console.log(
      "PROXY REQUEST:",
      targetUrl.href
    );

    const headers = {

      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131 Safari/537.36",

      "Accept":
        req.headers.accept ||
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",

      "Accept-Language":
        req.headers["accept-language"] ||
        "en-US,en;q=0.9"

    };

    const response =
      await fetch(
        targetUrl.href,
        {
          method: req.method,
          headers,
          redirect: "manual"
        }
      );

    console.log(
      "TARGET STATUS:",
      response.status
    );

    // --------------------------------------------------------
    // REDIRECT
    // --------------------------------------------------------

    if (
      response.status >= 300 &&
      response.status < 400
    ) {

      const location =
        response.headers.get("location");

      if (location) {

        const nextUrl =
          new URL(
            location,
            targetUrl.href
          ).href;

        if (!isAllowedUrl(nextUrl)) {

          return res.status(403).send(
            "Redirect destination blocked."
          );

        }

        return res.redirect(
          "/proxy?url=" +
          encodeURIComponent(nextUrl)
        );

      }

    }

    const contentType =
      response.headers.get(
        "content-type"
      ) || "";

    const data =
      Buffer.from(
        await response.arrayBuffer()
      );

    // --------------------------------------------------------
    // TARGET ERROR
    // --------------------------------------------------------

    if (response.status >= 400) {

      return res.status(response.status).send(`
<!doctype html>

<html>

<head>

<meta charset="utf-8">

<title>Proxy response</title>

<style>

body {
  font-family: Arial;
  padding: 40px;
  background: #f5f5f5;
}

.box {
  max-width: 700px;
  margin: auto;
  padding: 30px;
  background: white;
  border-radius: 12px;
  box-shadow: 0 3px 20px rgba(0,0,0,.1);
}

code {
  word-break: break-all;
}

</style>

</head>

<body>

<div class="box">

<h1>Target returned HTTP ${response.status}</h1>

<p>
The destination server returned an error.
</p>

<p>
URL:
</p>

<code>${escapeHtml(targetUrl.href)}</code>

<p>
Content-Type:
${escapeHtml(contentType)}
</p>

</div>

</body>

</html>
      `);

    }

    // --------------------------------------------------------
    // HTML REWRITING
    // --------------------------------------------------------

    if (
      contentType.includes("text/html")
    ) {

      let html =
        data.toString("utf8");

      // Remove CSP meta tags.

      html = html.replace(
        /<meta[^>]+http-equiv=["']Content-Security-Policy["'][^>]*>/gi,
        ""
      );

      // Rewrite href/src/action URLs.

      html = html.replace(
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
              !absolute.startsWith("http://") &&
              !absolute.startsWith("https://")
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

      html = html.replace(
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
                  item.trim()
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

      res.status(response.status);

      res.set(
        "Content-Type",
        "text/html; charset=utf-8"
      );

      return res.send(html);

    }

    // --------------------------------------------------------
    // OTHER RESOURCES
    // --------------------------------------------------------

    if (contentType) {

      res.set(
        "Content-Type",
        contentType
      );

    }

    res.status(response.status);

    return res.send(data);

  } catch (error) {

    console.error(
      "PROXY ERROR:",
      error
    );

    return res.status(502).send(`
<!doctype html>

<html>

<head>

<meta charset="utf-8">

<title>Proxy Error</title>

</head>

<body>

<h1>Proxy Error</h1>

<p>
${escapeHtml(
  error.message || String(error)
)}
</p>

</body>

</html>
    `);

  }

});

// ============================================================
// ESCAPE HTML
// ============================================================

function escapeHtml(value) {

  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");

}

// ============================================================
// HEALTH
// ============================================================

app.get("/health", (req, res) => {

  res.json({

    ok: true,
    http: true,
    websocket: true,
    streaming: true,
    browser: true,
    proxy: true

  });

});

// ============================================================
// WEBSOCKET STREAM
// ============================================================

const wss =
  new WebSocketServer({
    server,
    path: "/stream"
  });

wss.on("connection", socket => {

  console.log(
    "Streaming client connected"
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

      if (packetNumber >= 30) {

        clearInterval(interval);

        socket.send(
          JSON.stringify({
            type: "stream-complete"
          })
        );

      }

    }, 250);

  socket.on("message", message => {

    console.log(
      "Client message:",
      message.toString()
    );

  });

  socket.on("close", () => {

    clearInterval(interval);

    console.log(
      "Streaming client disconnected"
    );

  });

});

// ============================================================
// START
// ============================================================

server.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      "VPS Proxy running on port " +
      PORT
    );

  }
);
