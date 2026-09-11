import express from "express";
import path from "path";
import dns from "dns";
import net from "net";
import { fileURLToPath } from "url";

const app = express();

const PORT = process.env.PORT || 10000;
const HOST = "0.0.0.0";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PUBLIC_DIR = path.join(__dirname, "public");
const GAMES_DIR = path.join(PUBLIC_DIR, "games");

// ---------------------------------------------------------
// EXPRESS SETUP
// ---------------------------------------------------------

app.disable("x-powered-by");

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));

// ---------------------------------------------------------
// STATIC WEBSITE
// ---------------------------------------------------------

// Main XCloud website
app.use(express.static(PUBLIC_DIR));

// Games
app.use(
  "/games",
  express.static(GAMES_DIR, {
    index: "index.html"
  })
);

// /games -> main XCloud page
app.get("/games", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

app.get("/games/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

// ---------------------------------------------------------
// HEALTH
// ---------------------------------------------------------

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "XCloud",
    time: new Date().toISOString()
  });
});

// ---------------------------------------------------------
// NETWORK DEBUG
// ---------------------------------------------------------

app.get("/debug-network", async (req, res) => {
  const host = req.query.host || "example.com";

  try {
    const addresses = await dns.promises.lookup(host, {
      all: true,
      verbatim: false
    });

    res.json({
      ok: true,
      host,
      addresses
    });
  } catch (error) {
    res.status(500).json({
      ok: false,
      host,
      error: error.message
    });
  }
});

// ---------------------------------------------------------
// SSRF PROTECTION
// ---------------------------------------------------------

function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);

  if (parts.length !== 4 || parts.some(Number.isNaN)) {
    return false;
  }

  const [a, b] = parts;

  // 10.0.0.0/8
  if (a === 10) return true;

  // 127.0.0.0/8
  if (a === 127) return true;

  // 169.254.0.0/16
  if (a === 169 && b === 254) return true;

  // 172.16.0.0/12
  if (a === 172 && b >= 16 && b <= 31) return true;

  // 192.168.0.0/16
  if (a === 192 && b === 168) return true;

  // 0.0.0.0/8
  if (a === 0) return true;

  return false;
}

function isPrivateIPv6(ip) {
  const normalized = ip.toLowerCase();

  if (normalized === "::1") return true;
  if (normalized === "::") return true;

  // fc00::/7
  if (
    normalized.startsWith("fc") ||
    normalized.startsWith("fd")
  ) {
    return true;
  }

  // fe80::/10
  if (
    normalized.startsWith("fe8") ||
    normalized.startsWith("fe9") ||
    normalized.startsWith("fea") ||
    normalized.startsWith("feb")
  ) {
    return true;
  }

  return false;
}

function isPrivateAddress(address) {
  if (net.isIPv4(address)) {
    return isPrivateIPv4(address);
  }

  if (net.isIPv6(address)) {
    return isPrivateIPv6(address);
  }

  return true;
}

async function validateTarget(hostname) {
  const lower = hostname.toLowerCase();

  // Block localhost-style hostnames
  if (
    lower === "localhost" ||
    lower.endsWith(".localhost") ||
    lower === "local"
  ) {
    throw new Error("Blocked hostname");
  }

  const addresses = await dns.promises.lookup(hostname, {
    all: true,
    verbatim: false
  });

  if (!addresses.length) {
    throw new Error("Could not resolve hostname");
  }

  for (const item of addresses) {
    if (isPrivateAddress(item.address)) {
      throw new Error("Target resolves to a private address");
    }
  }

  return addresses;
}

// ---------------------------------------------------------
// COOKIE STORAGE
// ---------------------------------------------------------

const sessions = new Map();

function getSession(req) {
  let sessionId = req.headers["x-xcloud-session"];

  if (!sessionId || typeof sessionId !== "string") {
    sessionId =
      Math.random().toString(36).slice(2) +
      Math.random().toString(36).slice(2);
  }

  if (!sessions.has(sessionId)) {
    sessions.set(sessionId, {
      cookies: new Map(),
      created: Date.now()
    });
  }

  return {
    id: sessionId,
    data: sessions.get(sessionId)
  };
}

// Clean old sessions every 30 minutes
setInterval(() => {
  const now = Date.now();

  for (const [id, session] of sessions.entries()) {
    if (now - session.created > 1000 * 60 * 60 * 6) {
      sessions.delete(id);
    }
  }
}, 1000 * 60 * 30);

// ---------------------------------------------------------
// COOKIE HELPERS
// ---------------------------------------------------------

function parseSetCookie(cookieString) {
  if (!cookieString) return null;

  const firstPart = cookieString.split(";")[0];
  const separator = firstPart.indexOf("=");

  if (separator === -1) return null;

  const name = firstPart.slice(0, separator).trim();
  const value = firstPart.slice(separator + 1).trim();

  if (!name) return null;

  return {
    name,
    value
  };
}

function storeCookies(session, response) {
  const cookies = response.headers.getSetCookie
    ? response.headers.getSetCookie()
    : [];

  for (const cookie of cookies) {
    const parsed = parseSetCookie(cookie);

    if (!parsed) continue;

    if (parsed.value === "") {
      session.cookies.delete(parsed.name);
    } else {
      session.cookies.set(parsed.name, parsed.value);
    }
  }
}

function buildCookieHeader(session) {
  return Array.from(session.cookies.entries())
    .map(([name, value]) => `${name}=${value}`)
    .join("; ");
}

// ---------------------------------------------------------
// URL HELPERS
// ---------------------------------------------------------

function normalizeUrl(input) {
  if (!input) {
    throw new Error("Missing URL");
  }

  let value = input.trim();

  if (!/^https?:\/\//i.test(value)) {
    value = "https://" + value;
  }

  const url = new URL(value);

  if (!["http:", "https:"].includes(url.protocol)) {
    throw new Error("Only HTTP and HTTPS are supported");
  }

  return url;
}

// ---------------------------------------------------------
// HTML REWRITING
// ---------------------------------------------------------

function rewriteHtml(html, baseUrl) {
  const base = new URL(baseUrl);

  // Rewrite common HTML attributes
  html = html.replace(
    /\b(href|src|action|poster)=("([^"]*)"|'([^']*)')/gi,
    (match, attribute, quotedValue, doubleValue, singleValue) => {
      const value = doubleValue ?? singleValue;

      if (
        !value ||
        value.startsWith("#") ||
        value.startsWith("data:") ||
        value.startsWith("javascript:") ||
        value.startsWith("mailto:")
      ) {
        return match;
      }

      try {
        const absolute = new URL(value, base).href;

        return `${attribute}="/proxy?url=${encodeURIComponent(
          absolute
        )}"`;
      } catch {
        return match;
      }
    }
  );

  // Rewrite CSS url(...)
  html = html.replace(
    /url\(\s*(['"]?)([^'")]+)\1\s*\)/gi,
    (match, quote, value) => {
      if (
        value.startsWith("data:") ||
        value.startsWith("#") ||
        value.startsWith("http://") ||
        value.startsWith("https://")
      ) {
        try {
          const absolute = new URL(value, base).href;

          return `url("/proxy?url=${encodeURIComponent(
            absolute
          )}")`;
        } catch {
          return match;
        }
      }

      return match;
    }
  );

  // Inject a small helper script that redirects normal links
  // through the proxy.
  const injectedScript = `
<script>
(function () {
  document.addEventListener("click", function (event) {
    const link = event.target.closest("a");

    if (!link) return;

    const href = link.href;

    if (!href) return;

    if (
      href.startsWith("javascript:") ||
      href.startsWith("mailto:") ||
      href.startsWith("#")
    ) {
      return;
    }

    try {
      const url = new URL(href);

      if (url.protocol === "http:" || url.protocol === "https:") {
        event.preventDefault();
        window.location.href =
          "/proxy?url=" + encodeURIComponent(url.href);
      }
    } catch {}
  });
})();
</script>
`;

  if (/<\/body>/i.test(html)) {
    html = html.replace(/<\/body>/i, injectedScript + "</body>");
  } else {
    html += injectedScript;
  }

  return html;
}

// ---------------------------------------------------------
// PROXY
// ---------------------------------------------------------

app.all("/proxy", async (req, res) => {
  let targetUrl;

  try {
    targetUrl = normalizeUrl(req.query.url);
  } catch (error) {
    return res.status(400).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>XCloud Proxy</title>
        <style>
          body {
            background:#08090c;
            color:white;
            font-family:Arial,sans-serif;
            display:flex;
            align-items:center;
            justify-content:center;
            min-height:100vh;
            margin:0;
          }
          .box {
            max-width:600px;
            padding:35px;
            border:1px solid #292d35;
            border-radius:16px;
            background:#111419;
          }
          h1 { margin-top:0; }
          p { color:#9da4b1; }
        </style>
      </head>
      <body>
        <div class="box">
          <h1>Invalid URL</h1>
          <p>${escapeHtml(error.message)}</p>
        </div>
      </body>
      </html>
    `);
  }

  try {
    await validateTarget(targetUrl.hostname);
  } catch (error) {
    return res.status(403).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>XCloud Proxy</title>
        <style>
          body {
            background:#08090c;
            color:white;
            font-family:Arial,sans-serif;
            display:flex;
            align-items:center;
            justify-content:center;
            min-height:100vh;
            margin:0;
          }
          .box {
            max-width:600px;
            padding:35px;
            border:1px solid #292d35;
            border-radius:16px;
            background:#111419;
          }
          h1 { margin-top:0; }
          p { color:#9da4b1; }
        </style>
      </head>
      <body>
        <div class="box">
          <h1>Target blocked</h1>
          <p>${escapeHtml(error.message)}</p>
        </div>
      </body>
      </html>
    `);
  }

  const { id: sessionId, data: session } = getSession(req);

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20000);

  try {
    const headers = {
      "User-Agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131 Safari/537.36",
      "Accept":
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
      "Accept-Language":
        req.headers["accept-language"] || "en-US,en;q=0.9",
      "Cache-Control": "no-cache"
    };

    const cookieHeader = buildCookieHeader(session);

    if (cookieHeader) {
      headers.Cookie = cookieHeader;
    }

    // Forward a safe subset of request headers
    if (req.headers["content-type"]) {
      headers["Content-Type"] = req.headers["content-type"];
    }

    if (req.headers["referer"]) {
      headers.Referer = req.headers["referer"];
    }

    let body;

    if (!["GET", "HEAD"].includes(req.method)) {
      if (typeof req.body === "object" && req.body !== null) {
        body = JSON.stringify(req.body);
        headers["Content-Type"] =
          headers["Content-Type"] || "application/json";
      } else if (typeof req.body === "string") {
        body = req.body;
      }
    }

    const response = await fetch(targetUrl.href, {
      method: req.method,
      headers,
      body,
      redirect: "manual",
      signal: controller.signal
    });

    storeCookies(session, response);

    // -----------------------------------------------------
    // REDIRECTS
    // -----------------------------------------------------

    if (
      response.status >= 300 &&
      response.status < 400 &&
      response.headers.get("location")
    ) {
      const location = new URL(
        response.headers.get("location"),
        targetUrl
      );

      const redirectUrl =
        "/proxy?url=" + encodeURIComponent(location.href);

      res.setHeader("X-XCloud-Session", sessionId);
      return res.redirect(response.status, redirectUrl);
    }

    // -----------------------------------------------------
    // RESPONSE HEADERS
    // -----------------------------------------------------

    const contentType =
      response.headers.get("content-type") || "application/octet-stream";

    res.setHeader("X-XCloud-Session", sessionId);

    const headersToForward = [
      "content-type",
      "content-language",
      "cache-control",
      "etag",
      "last-modified",
      "content-disposition"
    ];

    for (const header of headersToForward) {
      const value = response.headers.get(header);

      if (value) {
        res.setHeader(header, value);
      }
    }

    // -----------------------------------------------------
    // HTML
    // -----------------------------------------------------

    if (
      contentType.includes("text/html") ||
      contentType.includes("application/xhtml+xml")
    ) {
      const text = await response.text();

      const rewritten = rewriteHtml(
        text,
        targetUrl.href
      );

      res.status(response.status).send(rewritten);
      return;
    }

    // -----------------------------------------------------
    // OTHER CONTENT
    // -----------------------------------------------------

    const arrayBuffer = await response.arrayBuffer();

    res.status(response.status).send(
      Buffer.from(arrayBuffer)
    );
  } catch (error) {
    console.error("Proxy error:", error);

    if (error.name === "AbortError") {
      return res.status(504).json({
        ok: false,
        error: "Target request timed out"
      });
    }

    return res.status(502).json({
      ok: false,
      error: "Proxy request failed",
      details: error.message
    });
  } finally {
    clearTimeout(timeout);
  }
});

// ---------------------------------------------------------
// ESCAPE HTML
// ---------------------------------------------------------

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// ---------------------------------------------------------
// 404
// ---------------------------------------------------------

app.use((req, res) => {
  if (req.accepts("html")) {
    return res.status(404).send(`
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <title>XCloud - 404</title>
        <style>
          * {
            box-sizing:border-box;
          }

          body {
            margin:0;
            min-height:100vh;
            display:flex;
            align-items:center;
            justify-content:center;
            background:#08090c;
            color:white;
            font-family:Arial,sans-serif;
          }

          .box {
            text-align:center;
            padding:40px;
          }

          h1 {
            font-size:80px;
            margin:0;
          }

          p {
            color:#8f96a3;
          }

          a {
            display:inline-block;
            margin-top:15px;
            padding:12px 20px;
            background:white;
            color:black;
            border-radius:8px;
            text-decoration:none;
            font-weight:700;
          }
        </style>
      </head>
      <body>
        <div class="box">
          <h1>404</h1>
          <p>Page not found.</p>
          <a href="/">Back to XCloud</a>
        </div>
      </body>
      </html>
    `);
  }

  res.status(404).json({
    ok: false,
    error: "Not found"
  });
});

// ---------------------------------------------------------
// START SERVER
// ---------------------------------------------------------

app.listen(PORT, HOST, () => {
  console.log("======================================");
  console.log("        XCLOUD SERVER ONLINE");
  console.log("======================================");
  console.log(`Port: ${PORT}`);
  console.log(`Public: ${PUBLIC_DIR}`);
  console.log(`Games: ${GAMES_DIR}`);
  console.log("--------------------------------------");
  console.log("Website:");
  console.log(`http://localhost:${PORT}/`);
  console.log("--------------------------------------");
  console.log("Games:");
  console.log(`http://localhost:${PORT}/games/`);
  console.log("--------------------------------------");
  console.log("XCloud Racer:");
  console.log(
    `http://localhost:${PORT}/games/xcloud-racer/`
  );
  console.log("--------------------------------------");
});
