```js
import express from "express";
import http from "http";
import https from "https";
import dns from "dns";
import crypto from "crypto";
import { WebSocketServer } from "ws";

const app = express();

const PORT = Number(process.env.PORT || 10000);

const sessions = new Map();

/*
 * Render / Node networking
 *
 * Force DNS resolution toward IPv4 first.
 * This avoids many VPS/container IPv6 connection problems.
 */
dns.setDefaultResultOrder("ipv4first");

/* -------------------------------------------------------
   Express
------------------------------------------------------- */

app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true, limit: "5mb" }));

app.use((req, _res, next) => {
  req.cookies = {};

  const cookieHeader = req.headers.cookie || "";

  for (const part of cookieHeader.split(";")) {
    const index = part.indexOf("=");

    if (index === -1) continue;

    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    if (name) {
      req.cookies[name] = value;
    }
  }

  next();
});

/* -------------------------------------------------------
   Helpers
------------------------------------------------------- */

function randomId() {
  return crypto.randomBytes(24).toString("hex");
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function createSession() {
  const id = randomId();

  sessions.set(id, {
    createdAt: Date.now(),
    cookies: new Map()
  });

  return id;
}

function getSession(req, res) {
  let id = req.cookies.proxy_session;

  if (!id || !sessions.has(id)) {
    id = createSession();

    res.cookie("proxy_session", id, {
      httpOnly: true,
      sameSite: "lax",
      secure: false,
      maxAge: 24 * 60 * 60 * 1000
    });
  }

  return sessions.get(id);
}

function getCookieHeader(session) {
  return [...session.cookies.entries()]
    .map(([name, value]) => `${name}=${value}`)
    .join("; ");
}

function storeCookies(session, headers) {
  const cookies = headers["set-cookie"];

  if (!cookies) return;

  for (const cookie of cookies) {
    const first = cookie.split(";")[0];

    const index = first.indexOf("=");

    if (index === -1) continue;

    const name = first.slice(0, index).trim();
    const value = first.slice(index + 1).trim();

    if (name) {
      session.cookies.set(name, value);
    }
  }
}

/* -------------------------------------------------------
   SSRF protection
------------------------------------------------------- */

function isPrivateIPv4(ip) {
  const p = ip.split(".").map(Number);

  if (p.length !== 4 || p.some(Number.isNaN)) {
    return false;
  }

  const [a, b] = p;

  return (
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 192 && b === 168) ||
    (a === 172 && b >= 16 && b <= 31)
  );
}

function isPrivateIPv6(ip) {
  const value = ip.toLowerCase();

  return (
    value === "::1" ||
    value.startsWith("fc") ||
    value.startsWith("fd") ||
    value.startsWith("fe80:")
  );
}

async function validateUrl(input) {
  let url;

  try {
    url = new URL(input);
  } catch {
    throw new Error("Invalid URL.");
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only HTTP and HTTPS are supported.");
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

  const addresses = await dns.promises.lookup(hostname, {
    all: true,
    verbatim: false
  });

  if (!addresses.length) {
    throw new Error("Could not resolve destination.");
  }

  for (const item of addresses) {
    if (
      isPrivateIPv4(item.address) ||
      isPrivateIPv6(item.address)
    ) {
      throw new Error(
        "Destination resolves to a private/local address."
      );
    }
  }

  return url;
}

/* -------------------------------------------------------
   IPv4 HTTP/HTTPS request
------------------------------------------------------- */

function requestUpstream(url, options = {}) {
  return new Promise((resolve, reject) => {
    const isHttps = url.protocol === "https:";

    const transport = isHttps ? https : http;

    const defaultPort = isHttps ? 443 : 80;

    const requestOptions = {
      protocol: url.protocol,

      hostname: url.hostname,

      /*
       * Important:
       * connect directly to the resolved IPv4 address.
       */
      port: url.port || defaultPort,

      method: options.method || "GET",

      path:
        url.pathname +
        url.search,

      headers: options.headers || {},

      timeout: 25000,

      family: 4,

      lookup(hostname, lookupOptions, callback) {
        dns.lookup(
          hostname,
          {
            family: 4
          },
          callback
        );
      }
    };

    const request = transport.request(
      requestOptions,
      response => {

        const chunks = [];

        response.on("data", chunk => {
          chunks.push(chunk);
        });

        response.on("end", () => {

          resolve({
            statusCode: response.statusCode || 502,

            headers: response.headers,

            body: Buffer.concat(chunks)
          });

        });

      }
    );

    request.on("timeout", () => {
      request.destroy(
        new Error(
          "Upstream connection timed out after 25 seconds."
        )
      );
    });

    request.on("error", error => {
      reject(error);
    });

    if (options.body) {
      request.write(options.body);
    }

    request.end();
  });
}

/* -------------------------------------------------------
   Input handling
------------------------------------------------------- */

function destinationFromInput(value) {
  value = String(value || "").trim();

  if (!value) {
    return null;
  }

  if (/^https?:\/\//i.test(value)) {
    return value;
  }

  if (
    /^[a-z0-9.-]+\.[a-z]{2,}(\/.*)?$/i.test(value)
  ) {
    return `https://${value}`;
  }

  return (
    "https://duckduckgo.com/?q=" +
    encodeURIComponent(value) +
    "&kl=se-sv"
  );
}

/* -------------------------------------------------------
   Homepage
------------------------------------------------------- */

app.get("/", (_req, res) => {
  res.redirect("/browser");
});

/* -------------------------------------------------------
   Browser UI
------------------------------------------------------- */

app.get("/browser", (_req, res) => {

  res.type("html").send(`<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
  name="viewport"
  content="width=device-width, initial-scale=1.0"
>

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
  font-family:
    Arial,
    Helvetica,
    sans-serif;
}

body {
  background: #f5f5f5;
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

  font-size: 19px;

  font-weight: 700;

  white-space: nowrap;
}

.top-search {
  flex: 1;

  display: flex;

  gap: 8px;
}

.top-search input {
  flex: 1;

  min-width: 0;

  height: 42px;

  border: none;

  border-radius: 8px;

  padding: 0 14px;

  font-size: 15px;

  outline: none;
}

button {
  border: none;

  background: #f97316;

  color: white;

  font-weight: 700;

  border-radius: 8px;

  cursor: pointer;
}

.top-search button {
  padding: 0 18px;
}

.home {
  height: calc(100vh - 64px);

  display: flex;

  align-items: center;

  justify-content: center;

  padding: 20px;
}

.card {
  width: min(760px, 100%);

  text-align: center;
}

.search-engine {
  font-size: 48px;

  font-weight: 800;

  color: #111827;

  margin-bottom: 8px;
}

.subtitle {
  color: #6b7280;

  margin-bottom: 28px;
}

.main-search {
  display: flex;

  gap: 10px;
}

.main-search input {
  flex: 1;

  height: 54px;

  border: 1px solid #d1d5db;

  border-radius: 12px;

  padding: 0 18px;

  font-size: 17px;

  outline: none;
}

.main-search input:focus {
  border-color: #f97316;
}

.main-search button {
  padding: 0 24px;

  font-size: 16px;
}

.hint {
  margin-top: 16px;

  color: #9ca3af;

  font-size: 13px;
}

#browserFrame {
  display: none;

  position: absolute;

  top: 64px;

  left: 0;

  width: 100%;

  height: calc(100vh - 64px);

  border: none;

  background: white;
}

</style>

</head>

<body>

<div class="topbar">

  <div class="logo">
    Web Gateway
  </div>

  <form
    class="top-search"
    id="topSearch"
  >

    <input
      id="topInput"
      autocomplete="off"
      placeholder="Search DuckDuckGo or enter URL..."
    >

    <button type="submit">
      Go
    </button>

  </form>

</div>

<div
  class="home"
  id="home"
>

  <div class="card">

    <div class="search-engine">
      DuckDuckGo
    </div>

    <div class="subtitle">
      Search the web through your Render gateway
    </div>

    <form
      class="main-search"
      id="mainSearch"
    >

      <input
        id="mainInput"
        autocomplete="off"
        autofocus
        placeholder="Search the web or enter a website..."
      >

      <button type="submit">
        Search
      </button>

    </form>

    <div class="hint">
      Search something or enter example.com
    </div>

  </div>

</div>

<iframe
  id="browserFrame"
  sandbox="allow-forms allow-modals allow-popups allow-presentation allow-same-origin allow-scripts"
></iframe>

<script>

function makeDestination(value) {

  value = value.trim();

  if (!value) {
    return null;
  }

  if (/^https?:\\/\\//i.test(value)) {
    return value;
  }

  if (
    /^[a-z0-9.-]+\\.[a-z]{2,}(\\/.*)?$/i.test(value)
  ) {
    return "https://" + value;
  }

  return (
    "https://duckduckgo.com/?q=" +
    encodeURIComponent(value) +
    "&kl=se-sv"
  );
}

function openDestination(value) {

  const destination =
    makeDestination(value);

  if (!destination) {
    return;
  }

  const frame =
    document.getElementById("browserFrame");

  const home =
    document.getElementById("home");

  home.style.display = "none";

  frame.style.display = "block";

  frame.src =
    "/proxy?url=" +
    encodeURIComponent(destination);
}

document
  .getElementById("mainSearch")
  .addEventListener(
    "submit",
    event => {

      event.preventDefault();

      openDestination(
        document.getElementById("mainInput").value
      );

    }
  );

document
  .getElementById("topSearch")
  .addEventListener(
    "submit",
    event => {

      event.preventDefault();

      const value =
        document.getElementById("topInput").value;

      document.getElementById("mainInput").value =
        value;

      openDestination(value);

    }
  );

</script>

</body>

</html>`);

});

/* -------------------------------------------------------
   Proxy endpoint
------------------------------------------------------- */

app.all("/proxy", async (req, res) => {

  const rawUrl = req.query.url;

  if (!rawUrl) {

    return res.status(400).json({
      error: "Missing URL"
    });

  }

  let destination;

  try {

    destination =
      await validateUrl(rawUrl);

  } catch (error) {

    return res.status(400).json({

      error: "Invalid destination",

      message: error.message

    });

  }

  const session =
    getSession(req, res);

  try {

    const headers = {

      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131 Safari/537.36",

      "Accept":
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",

      "Accept-Language":
        "sv-SE,sv;q=0.9,en-US;q=0.8,en;q=0.7",

      "Connection":
        "close"

    };

    const cookieHeader =
      getCookieHeader(session);

    if (cookieHeader) {
      headers.Cookie = cookieHeader;
    }

    /*
     * Forward content type for POST requests.
     */

    if (req.headers["content-type"]) {

      headers["Content-Type"] =
        req.headers["content-type"];

    }

    let body = null;

    if (!["GET", "HEAD"].includes(req.method)) {

      if (
        typeof req.body === "string"
      ) {

        body = req.body;

      } else if (
        req.headers["content-type"]?.includes(
          "application/json"
        )
      ) {

        body =
          JSON.stringify(req.body || {});

      } else if (
        req.headers["content-type"]?.includes(
          "application/x-www-form-urlencoded"
        )
      ) {

        body =
          new URLSearchParams(
            req.body || {}
          ).toString();

      }

      if (body) {
        headers["Content-Length"] =
          Buffer.byteLength(body);
      }

    }

    console.log("");
    console.log(
      "[PROXY]",
      req.method,
      destination.href
    );

    const upstream =
      await requestUpstream(
        destination,
        {
          method: req.method,
          headers,
          body
        }
      );

    console.log(
      "[UPSTREAM]",
      upstream.statusCode,
      destination.hostname
    );

    storeCookies(
      session,
      upstream.headers
    );

    /*
     * Redirects
     */

    if (
      upstream.statusCode >= 300 &&
      upstream.statusCode < 400
    ) {

      const location =
        upstream.headers.location;

      if (location) {

        const redirected =
          new URL(
            location,
            destination
          );

        await validateUrl(
          redirected.href
        );

        return res.redirect(
          upstream.statusCode,
          "/proxy?url=" +
          encodeURIComponent(
            redirected.href
          )
        );
      }
    }

    /*
     * Copy safe response headers.
     */

    const blockedHeaders = new Set([
      "content-length",
      "content-encoding",
      "transfer-encoding",
      "connection",
      "keep-alive",
      "x-frame-options",
      "content-security-policy"
    ]);

    for (
      const [key, value] of
      Object.entries(upstream.headers)
    ) {

      if (
        blockedHeaders.has(
          key.toLowerCase()
        )
      ) {
        continue;
      }

      if (value === undefined) {
        continue;
      }

      res.setHeader(key, value);
    }

    /*
     * HTML rewriting
     */

    const contentType =
      String(
        upstream.headers["content-type"] || ""
      ).toLowerCase();

    if (
      contentType.includes("text/html") ||
      contentType.includes("application/xhtml+xml")
    ) {

      let html =
        upstream.body.toString("utf8");

      html =
        rewriteHtml(
          html,
          destination.href
        );

      return res
        .status(upstream.statusCode)
        .type("html")
        .send(html);
    }

    /*
     * Images, CSS, JS, JSON, etc.
     */

    return res
      .status(upstream.statusCode)
      .send(upstream.body);

  } catch (error) {

    console.error("");
    console.error(
      "========== PROXY ERROR =========="
    );

    console.error(
      "URL:",
      destination.href
    );

    console.error(
      "Message:",
      error.message
    );

    console.error(
      "Code:",
      error.code
    );

    console.error(
      "================================="
    );

    return res.status(502).json({

      error: "Bad gateway",

      message:
        error.message ||
        "Connection to destination failed.",

      code:
        error.code || null

    });

  }

});

/* -------------------------------------------------------
   HTML URL rewriting
------------------------------------------------------- */

function rewriteHtml(
  html,
  baseUrl
) {

  const base =
    new URL(baseUrl);

  /*
   * Remove CSP and base tags.
   */

  html =
    html.replace(
      /<meta[^>]+http-equiv=["']?Content-Security-Policy["']?[^>]*>/gi,
      ""
    );

  html =
    html.replace(
      /<base[^>]*>/gi,
      ""
    );

  /*
   * href / src / action
   */

  html =
    html.replace(
      /\b(href|src|action)=("([^"]*)"|'([^']*)')/gi,
      (
        match,
        attribute,
        wrapper,
        doubleValue,
        singleValue
      ) => {

        const value =
          doubleValue ??
          singleValue ??
          "";

        const rewritten =
          rewriteUrl(
            value,
            base
          );

        if (!rewritten) {
          return match;
        }

        return (
          attribute +
          '="' +
          escapeHtml(rewritten) +
          '"'
        );

      }
    );

  /*
   * srcset
   */

  html =
    html.replace(
      /\bsrcset=("([^"]*)"|'([^']*)')/gi,
      (
        match,
        wrapper,
        doubleValue,
        singleValue
      ) => {

        const value =
          doubleValue ??
          singleValue ??
          "";

        const rewritten =
          value
            .split(",")
            .map(item => {

              const pieces =
                item.trim().split(/\s+/);

              if (!pieces[0]) {
                return item;
              }

              const url =
                rewriteUrl(
                  pieces[0],
                  base
                );

              if (!url) {
                return item;
              }

              pieces[0] = url;

              return pieces.join(" ");

            })
            .join(", ");

        return (
          'srcset="' +
          escapeHtml(rewritten) +
          '"'
        );

      }
    );

  /*
   * Keep navigation inside the proxy.
   */

  const navigationScript = `
<script>
(function () {

  document.addEventListener(
    "click",
    function (event) {

      const link =
        event.target.closest("a");

      if (!link) {
        return;
      }

      const href =
        link.getAttribute("href");

      if (!href) {
        return;
      }

      if (
        href.startsWith("#") ||
        href.startsWith("javascript:") ||
        href.startsWith("mailto:") ||
        href.startsWith("tel:")
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
            encodeURIComponent(
              absolute
            );

        }

      } catch (_) {}

    },
    true
  );

})();
</script>
`;

  if (/<\\/body>/i.test(html)) {

    html =
      html.replace(
        /<\\/body>/i,
        navigationScript +
        "</body>"
      );

  } else {

    html += navigationScript;

  }

  return html;
}

function rewriteUrl(
  value,
  base
) {

  const trimmed =
    String(value || "").trim();

  if (!trimmed) {
    return null;
  }

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
      new URL(
        trimmed,
        base
      );

    if (
      !["http:", "https:"].includes(
        absolute.protocol
      )
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
   Network diagnostics
------------------------------------------------------- */

app.get(
  "/debug-network",
  async (_req, res) => {

    const results = {};

    for (
      const target of [
        "https://example.com",
        "https://duckduckgo.com"
      ]
    ) {

      try {

        const url =
          await validateUrl(target);

        const start =
          Date.now();

        const response =
          await requestUpstream(
            url,
            {
              method: "HEAD",
              headers: {
                "User-Agent":
                  "XCloud-Test-Proxy/1.0"
              }
            }
          );

        results[target] = {

          ok: true,

          status:
            response.statusCode,

          timeMs:
            Date.now() - start

        };

      } catch (error) {

        results[target] = {

          ok: false,

          message:
            error.message,

          code:
            error.code || null

        };

      }

    }

    res.json({
      runtime: "Render",
      node: process.version,
      results
    });

  }
);

/* -------------------------------------------------------
   Health
------------------------------------------------------- */

app.get("/health", (_req, res) => {

  res.json({

    ok: true,

    service:
      "xcloud-test-proxy",

    runtime:
      "render",

    node:
      process.version,

    time:
      new Date().toISOString()

  });

});

/* -------------------------------------------------------
   WebSocket test
------------------------------------------------------- */

const wss =
  new WebSocketServer({
    noServer: true
  });

const server =
  http.createServer(app);

server.on(
  "upgrade",
  (request, socket, head) => {

    const url =
      new URL(
        request.url,
        `http://${request.headers.host}`
      );

    if (
      url.pathname !== "/stream"
    ) {

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

  }
);

wss.on(
  "connection",
  ws => {

    let count = 0;

    const interval =
      setInterval(() => {

        if (
          ws.readyState !== ws.OPEN
        ) {

          clearInterval(interval);

          return;
        }

        count++;

        ws.send(
          JSON.stringify({

            type: "packet",

            number: count,

            timestamp:
              Date.now(),

            message:
              "Render WebSocket test"

          })
        );

        if (count >= 30) {

          clearInterval(interval);

          ws.send(
            JSON.stringify({
              type: "complete"
            })
          );

          ws.close();

        }

      }, 250);

    ws.on(
      "close",
      () => {
        clearInterval(interval);
      }
    );

  }
);

/* -------------------------------------------------------
   Session cleanup
------------------------------------------------------- */

setInterval(
  () => {

    const now =
      Date.now();

    for (
      const [id, session]
      of sessions
    ) {

      if (
        now - session.createdAt >
        24 * 60 * 60 * 1000
      ) {

        sessions.delete(id);

      }

    }

  },
  60 * 60 * 1000
);

/* -------------------------------------------------------
   Start
------------------------------------------------------- */

server.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log("");
    console.log(
      "================================"
    );
    console.log(
      "XCloud Web Gateway"
    );
    console.log(
      "================================"
    );
    console.log(
      "Port:",
      PORT
    );
    console.log(
      "Node:",
      process.version
    );
    console.log(
      "IPv4-first networking: enabled"
    );
    console.log(
      "================================"
    );

  }
);
```
