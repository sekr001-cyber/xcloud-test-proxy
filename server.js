import express from "express";
import http from "http";
import https from "https";
import dns from "dns";
import dnsPromises from "dns/promises";
import net from "net";
import crypto from "crypto";

dns.setDefaultResultOrder("ipv4first");

const app = express();

const PORT = Number(process.env.PORT || 10000);
const TIMEOUT = 30000;
const MAX_BODY = 20 * 1024 * 1024;

const sessions = new Map();

/* =========================================================
   EXPRESS
   ========================================================= */

app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true, limit: "5mb" }));

/* =========================================================
   SESSION / COOKIES
   ========================================================= */

function createSession() {
  const id = crypto.randomBytes(24).toString("hex");

  const session = {
    cookies: new Map(),
    created: Date.now()
  };

  sessions.set(id, session);

  return {
    id,
    session
  };
}

function getSession(req, res) {
  const existing = req.headers["x-proxy-session"];

  if (
    typeof existing === "string" &&
    sessions.has(existing)
  ) {
    return {
      id: existing,
      session: sessions.get(existing)
    };
  }

  const created = createSession();

  res.setHeader("X-Proxy-Session", created.id);

  return created;
}

function cookieHeader(session) {
  const cookies = [];

  for (const entry of session.cookies.entries()) {
    cookies.push(entry[0] + "=" + entry[1]);
  }

  return cookies.join("; ");
}

function storeCookies(session, headers) {
  if (!headers) {
    return;
  }

  const list = Array.isArray(headers) ? headers : [headers];

  for (const item of list) {
    const first = String(item).split(";")[0];
    const separator = first.indexOf("=");

    if (separator < 1) {
      continue;
    }

    const name = first.slice(0, separator).trim();
    const value = first.slice(separator + 1).trim();

    if (name) {
      session.cookies.set(name, value);
    }
  }
}

/* =========================================================
   SSRF PROTECTION
   ========================================================= */

function isPrivateIPv4(ip) {
  const p = ip.split(".").map(Number);

  if (p.length !== 4 || p.some(Number.isNaN)) {
    return true;
  }

  if (p[0] === 10) return true;
  if (p[0] === 127) return true;
  if (p[0] === 0) return true;

  if (p[0] === 169 && p[1] === 254) {
    return true;
  }

  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) {
    return true;
  }

  if (p[0] === 192 && p[1] === 168) {
    return true;
  }

  return false;
}

function isBlockedIP(ip) {
  if (net.isIPv4(ip)) {
    return isPrivateIPv4(ip);
  }

  if (net.isIPv6(ip)) {
    const value = ip.toLowerCase();

    if (value === "::1") return true;
    if (value.startsWith("fc")) return true;
    if (value.startsWith("fd")) return true;
    if (value.startsWith("fe80:")) return true;

    return false;
  }

  return true;
}

async function checkTarget(url) {
  if (
    url.protocol !== "http:" &&
    url.protocol !== "https:"
  ) {
    throw new Error("Only HTTP and HTTPS are supported");
  }

  const hostname = url.hostname.toLowerCase();

  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost")
  ) {
    throw new Error("Localhost targets are blocked");
  }

  if (net.isIP(hostname)) {
    if (isBlockedIP(hostname)) {
      throw new Error("Private IP targets are blocked");
    }

    return;
  }

  const addresses = await dnsPromises.lookup(hostname, {
    all: true,
    verbatim: false
  });

  if (!addresses.length) {
    throw new Error("DNS returned no addresses");
  }

  for (const address of addresses) {
    if (isBlockedIP(address.address)) {
      throw new Error(
        "Target resolves to a private or local address"
      );
    }
  }
}

/* =========================================================
   OUTBOUND REQUEST
   ========================================================= */

function requestTarget(url, method, headers, body) {
  return new Promise(function (resolve, reject) {
    const secure = url.protocol === "https:";
    const transport = secure ? https : http;

    const options = {
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port
        ? Number(url.port)
        : secure
          ? 443
          : 80,
      path: url.pathname + url.search,
      method: method,
      headers: headers,
      family: 4,
      timeout: TIMEOUT
    };

    const request = transport.request(
      options,
      function (response) {
        const chunks = [];
        let size = 0;

        response.on("data", function (chunk) {
          size += chunk.length;

          if (size > MAX_BODY) {
            request.destroy(
              new Error("Response exceeded size limit")
            );
            return;
          }

          chunks.push(chunk);
        });

        response.on("end", function () {
          resolve({
            status: response.statusCode || 502,
            headers: response.headers,
            body: Buffer.concat(chunks)
          });
        });

        response.on("error", reject);
      }
    );

    request.on("timeout", function () {
      request.destroy(
        new Error("Upstream request timed out")
      );
    });

    request.on("error", function (error) {
      reject(error);
    });

    if (body && body.length) {
      request.write(body);
    }

    request.end();
  });
}

/* =========================================================
   HTML REWRITING
   ========================================================= */

function makeAbsolute(value, base) {
  try {
    return new URL(value, base).toString();
  } catch {
    return null;
  }
}

function proxyLink(url) {
  return "/proxy?url=" + encodeURIComponent(url);
}

function rewriteHtml(html, baseUrl) {
  let result = html;

  result = result.replace(
    /<base\s+[^>]*>/gi,
    ""
  );

  result = result.replace(
    /(href|src|action|poster)=["']([^"']+)["']/gi,
    function (match, attribute, value) {
      const lower = value.toLowerCase();

      if (
        lower.startsWith("#") ||
        lower.startsWith("data:") ||
        lower.startsWith("javascript:") ||
        lower.startsWith("mailto:") ||
        lower.startsWith("tel:")
      ) {
        return match;
      }

      const absolute = makeAbsolute(value, baseUrl);

      if (!absolute) {
        return match;
      }

      if (
        !absolute.startsWith("http://") &&
        !absolute.startsWith("https://")
      ) {
        return match;
      }

      return (
        attribute +
        '="' +
        proxyLink(absolute) +
        '"'
      );
    }
  );

  result = result.replace(
    /url\(\s*["']?([^)"']+)["']?\s*\)/gi,
    function (match, value) {
      const lower = value.toLowerCase();

      if (
        lower.startsWith("data:") ||
        lower.startsWith("http://") ||
        lower.startsWith("https://")
      ) {
        return match;
      }

      const absolute = makeAbsolute(value, baseUrl);

      if (!absolute) {
        return match;
      }

      return "url(" + proxyLink(absolute) + ")";
    }
  );

  result = result.replace(
    /<meta[^>]+http-equiv=["']Content-Security-Policy["'][^>]*>/gi,
    ""
  );

  return result;
}

/* =========================================================
   PROXY ROUTE
   ========================================================= */

app.all("/proxy", async function (req, res) {
  const raw = req.query.url;

  if (!raw || typeof raw !== "string") {
    return res.status(400).json({
      error: "Missing url",
      example: "/proxy?url=https://example.com"
    });
  }

  let target;

  try {
    target = new URL(raw);
  } catch {
    return res.status(400).json({
      error: "Invalid URL"
    });
  }

  try {
    await checkTarget(target);

    const sessionInfo = getSession(req, res);
    const session = sessionInfo.session;

    const headers = {};

    const allowed = [
      "accept",
      "accept-language",
      "content-type",
      "referer",
      "origin",
      "user-agent"
    ];

    for (const name of allowed) {
      const value = req.headers[name];

      if (value) {
        headers[name] = value;
      }
    }

    headers["user-agent"] =
      headers["user-agent"] ||
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131 Safari/537.36";

    const cookies = cookieHeader(session);

    if (cookies) {
      headers.cookie = cookies;
    }

    let body = null;

    if (
      req.method !== "GET" &&
      req.method !== "HEAD"
    ) {
      if (typeof req.body === "string") {
        body = Buffer.from(req.body);
      } else if (req.body && typeof req.body === "object") {
        const contentType = String(
          req.headers["content-type"] || ""
        );

        if (
          contentType.includes("application/json")
        ) {
          body = Buffer.from(
            JSON.stringify(req.body)
          );
        } else {
          body = Buffer.from(
            new URLSearchParams(req.body).toString()
          );
        }
      }
    }

    const upstream = await requestTarget(
      target,
      req.method,
      headers,
      body
    );

    storeCookies(
      session,
      upstream.headers["set-cookie"]
    );

    /* ---------- REDIRECT ---------- */

    if (
      upstream.headers.location &&
      [301, 302, 303, 307, 308].includes(
        upstream.status
      )
    ) {
      const destination = makeAbsolute(
        upstream.headers.location,
        target.toString()
      );

      if (destination) {
        return res.redirect(
          upstream.status,
          "/proxy?url=" +
            encodeURIComponent(destination)
        );
      }
    }

    /* ---------- BODY ---------- */

    let responseBody = upstream.body;

    const contentType = String(
      upstream.headers["content-type"] || ""
    ).toLowerCase();

    if (contentType.includes("text/html")) {
      const text = responseBody.toString("utf8");

      responseBody = Buffer.from(
        rewriteHtml(
          text,
          target.toString()
        ),
        "utf8"
      );
    }

    /* ---------- HEADERS ---------- */

    const blockedHeaders = new Set([
      "content-length",
      "content-encoding",
      "transfer-encoding",
      "connection",
      "keep-alive",
      "content-security-policy",
      "x-frame-options",
      "set-cookie"
    ]);

    for (const key of Object.keys(
      upstream.headers
    )) {
      if (
        blockedHeaders.has(key.toLowerCase())
      ) {
        continue;
      }

      const value = upstream.headers[key];

      if (value !== undefined) {
        res.setHeader(key, value);
      }
    }

    res.status(upstream.status);

    res.setHeader(
      "X-Proxy-Upstream",
      target.hostname
    );

    res.end(responseBody);
  } catch (error) {
    console.error(
      "[PROXY ERROR]",
      error
    );

    return res.status(502).json({
      error: "Bad gateway",
      message:
        error.message ||
        "Unknown upstream error",
      target: target.toString()
    });
  }
});

/* =========================================================
   BROWSER
   ========================================================= */

app.get("/", function (req, res) {
  res.redirect("/browser");
});

app.get("/browser", function (req, res) {
  const html = [
    "<!DOCTYPE html>",
    "<html>",
    "<head>",
    '<meta charset="UTF-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1">',
    "<title>XCloud Browser</title>",
    "<style>",
    "*{box-sizing:border-box}",
    "body{margin:0;background:#111;color:#fff;font-family:Arial,sans-serif}",
    ".bar{height:64px;background:#1b1b1b;border-bottom:1px solid #333;display:flex;align-items:center;gap:12px;padding:10px 14px}",
    ".logo{font-size:18px;font-weight:bold;white-space:nowrap}",
    "form{display:flex;flex:1;gap:8px}",
    "input{flex:1;background:#292929;color:white;border:1px solid #444;border-radius:8px;padding:12px;font-size:15px;outline:none}",
    "button{background:white;color:#111;border:0;border-radius:8px;padding:0 18px;font-weight:bold;cursor:pointer}",
    ".main{height:calc(100vh - 64px);display:flex;align-items:center;justify-content:center;text-align:center}",
    ".box{width:min(700px,90%)}",
    "h1{font-size:44px;margin:0 0 10px}",
    "p{color:#aaa}",
    ".search{height:50px;margin-top:24px}",
    ".search button{height:50px}",
    "</style>",
    "</head>",
    "<body>",
    '<div class="bar">',
    '<div class="logo">XCloud Browser</div>',
    '<form id="nav">',
    '<input id="address" placeholder="Search DuckDuckGo or enter a URL..." autocomplete="off">',
    "<button>Go</button>",
    "</form>",
    "</div>",
    '<div class="main">',
    '<div class="box">',
    "<h1>DuckDuckGo</h1>",
    "<p>Search the web or enter a website address.</p>",
    '<form id="search" class="search">',
    '<input id="query" placeholder="Search the web..." autocomplete="off">',
    "<button>Search</button>",
    "</form>",
    "</div>",
    "</div>",
    "<script>",
    "function go(value){",
    "value=value.trim();",
    "if(!value)return;",
    "var target;",
    "if(value.indexOf('http://')===0||value.indexOf('https://')===0){",
    "target=value;",
    "}else if(value.indexOf('.')!==-1&&!value.includes(' ')){",
    "target='https://'+value;",
    "}else{",
    "target='https://duckduckgo.com/?q='+encodeURIComponent(value)+'&kl=se-sv';",
    "}",
    "window.location.href='/proxy?url='+encodeURIComponent(target);",
    "}",
    "document.getElementById('nav').addEventListener('submit',function(e){",
    "e.preventDefault();",
    "go(document.getElementById('address').value);",
    "});",
    "document.getElementById('search').addEventListener('submit',function(e){",
    "e.preventDefault();",
    "go(document.getElementById('query').value);",
    "});",
    "</script>",
    "</body>",
    "</html>"
  ].join("");

  res.type("html").send(html);
});

/* =========================================================
   HEALTH
   ========================================================= */

app.get("/health", function (req, res) {
  res.json({
    ok: true,
    service: "xcloud-test-proxy",
    runtime: "render",
    node: process.version,
    sessions: sessions.size,
    time: new Date().toISOString()
  });
});

/* =========================================================
   NETWORK TEST
   ========================================================= */

app.get("/debug-network", async function (req, res) {
  const hosts = [
    "example.com",
    "duckduckgo.com"
  ];

  const results = [];

  for (const hostname of hosts) {
    const result = {
      hostname: hostname
    };

    try {
      const addresses =
        await dnsPromises.lookup(
          hostname,
          {
            all: true,
            verbatim: false
          }
        );

      result.dns = addresses;

      const target =
        new URL(
          "https://" +
          hostname +
          "/"
        );

      const start = Date.now();

      const response =
        await requestTarget(
          target,
          "GET",
          {
            accept: "*/*",
            "user-agent":
              "XCloud-Debug/1.0"
          },
          null
        );

      result.status =
        response.status;

      result.ms =
        Date.now() - start;
    } catch (error) {
      result.error =
        error.message;

      if (error.code) {
        result.code =
          error.code;
      }
    }

    results.push(result);
  }

  res.json({
    ok: true,
    node: process.version,
    ipv4First: true,
    results: results
  });
});

/* =========================================================
   404
   ========================================================= */

app.use(function (req, res) {
  res.status(404).json({
    error: "Not found"
  });
});

/* =========================================================
   START
   ========================================================= */

app.listen(
  PORT,
  "0.0.0.0",
  function () {
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
      "Port: " + PORT
    );
    console.log(
      "Node: " + process.version
    );
    console.log(
      "IPv4-first: enabled"
    );
    console.log(
      "DuckDuckGo: enabled"
    );
    console.log(
      "Proxy: enabled"
    );
    console.log(
      "================================"
    );
    console.log("");
  }
);
