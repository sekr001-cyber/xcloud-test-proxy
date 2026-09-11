import express from "express";
import http from "http";
import https from "https";
import dns from "dns";
import dnsPromises from "dns/promises";
import crypto from "crypto";
import net from "net";

dns.setDefaultResultOrder("ipv4first");

const app = express();

const PORT = Number(process.env.PORT || 10000);
const PROXY_KEY = process.env.PROXY_KEY || "";
const REQUEST_TIMEOUT = 30000;

const sessions = new Map();

app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true, limit: "5mb" }));

/* =========================================================
   BASIC HELPERS
   ========================================================= */

function makeId() {
  return crypto.randomBytes(24).toString("hex");
}

function getSession(req, res) {
  let id = req.headers["x-proxy-session"];

  if (!id || typeof id !== "string" || !sessions.has(id)) {
    id = makeId();

    sessions.set(id, {
      cookies: new Map(),
      created: Date.now()
    });

    res.setHeader("X-Proxy-Session", id);
  }

  return sessions.get(id);
}

function getCookieHeader(session) {
  const values = [];

  for (const entry of session.cookies.entries()) {
    values.push(entry[0] + "=" + entry[1]);
  }

  return values.join("; ");
}

function saveCookies(session, setCookieHeaders) {
  if (!setCookieHeaders) {
    return;
  }

  const list = Array.isArray(setCookieHeaders)
    ? setCookieHeaders
    : [setCookieHeaders];

  for (const cookieString of list) {
    const firstPart = String(cookieString).split(";")[0];
    const separator = firstPart.indexOf("=");

    if (separator <= 0) {
      continue;
    }

    const name = firstPart.slice(0, separator).trim();
    const value = firstPart.slice(separator + 1).trim();

    if (!name) {
      continue;
    }

    session.cookies.set(name, value);
  }
}

function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);

  if (parts.length !== 4 || parts.some(Number.isNaN)) {
    return false;
  }

  if (parts[0] === 10) {
    return true;
  }

  if (parts[0] === 127) {
    return true;
  }

  if (parts[0] === 169 && parts[1] === 254) {
    return true;
  }

  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) {
    return true;
  }

  if (parts[0] === 192 && parts[1] === 168) {
    return true;
  }

  if (parts[0] === 0) {
    return true;
  }

  return false;
}

function isBlockedAddress(address) {
  if (net.isIPv4(address)) {
    return isPrivateIPv4(address);
  }

  if (net.isIPv6(address)) {
    const lower = address.toLowerCase();

    if (lower === "::1") {
      return true;
    }

    if (lower.startsWith("fc") || lower.startsWith("fd")) {
      return true;
    }

    if (lower.startsWith("fe80:")) {
      return true;
    }

    return false;
  }

  return true;
}

async function validateTarget(urlObject) {
  if (!urlObject) {
    throw new Error("Invalid URL");
  }

  if (urlObject.protocol !== "http:" && urlObject.protocol !== "https:") {
    throw new Error("Only HTTP and HTTPS URLs are allowed");
  }

  const hostname = urlObject.hostname;

  if (!hostname) {
    throw new Error("Missing hostname");
  }

  const lowerHost = hostname.toLowerCase();

  if (
    lowerHost === "localhost" ||
    lowerHost.endsWith(".localhost") ||
    lowerHost === "local"
  ) {
    throw new Error("Local targets are blocked");
  }

  const records = await dnsPromises.lookup(hostname, {
    all: true,
    verbatim: false
  });

  if (!records.length) {
    throw new Error("DNS lookup returned no addresses");
  }

  for (const record of records) {
    if (isBlockedAddress(record.address)) {
      throw new Error("Target resolves to a private or local network");
    }
  }

  return records;
}

/* =========================================================
   HTTP REQUEST
   ========================================================= */

function requestTarget(urlObject, method, headers, body, resolvedAddresses) {
  return new Promise(function (resolve, reject) {
    const isHttps = urlObject.protocol === "https:";
    const transport = isHttps ? https : http;

    const hostname = urlObject.hostname;

    const options = {
      protocol: urlObject.protocol,
      hostname: resolvedAddresses[0].address,
      port: urlObject.port
        ? Number(urlObject.port)
        : isHttps
          ? 443
          : 80,
      method: method,
      path: urlObject.pathname + urlObject.search,
      headers: {
        ...headers,
        Host: hostname
      },
      timeout: REQUEST_TIMEOUT,
      servername: isHttps ? hostname : undefined
    };

    const request = transport.request(options, function (response) {
      const chunks = [];

      response.on("data", function (chunk) {
        chunks.push(chunk);
      });

      response.on("end", function () {
        resolve({
          statusCode: response.statusCode || 502,
          headers: response.headers,
          body: Buffer.concat(chunks)
        });
      });
    });

    request.on("timeout", function () {
      request.destroy(new Error("Upstream request timed out"));
    });

    request.on("error", function (error) {
      reject(error);
    });

    if (body && body.length > 0) {
      request.write(body);
    }

    request.end();
  });
}

/* =========================================================
   HTML REWRITING
   ========================================================= */

function absoluteUrl(value, baseUrl) {
  try {
    return new URL(value, baseUrl).toString();
  } catch {
    return null;
  }
}

function proxyUrl(url) {
  return "/proxy?url=" + encodeURIComponent(url);
}

function rewriteHtml(html, baseUrl) {
  let output = html;

  output = output.replace(
    /<base\s+[^>]*href=["']([^"']+)["'][^>]*>/gi,
    ""
  );

  output = output.replace(
    /(href|src|action|poster)=["']([^"']+)["']/gi,
    function (match, attribute, value) {
      if (
        value.startsWith("#") ||
        value.startsWith("data:") ||
        value.startsWith("javascript:") ||
        value.startsWith("mailto:") ||
        value.startsWith("tel:")
      ) {
        return match;
      }

      const absolute = absoluteUrl(value, baseUrl);

      if (!absolute) {
        return match;
      }

      if (
        !absolute.startsWith("http://") &&
        !absolute.startsWith("https://")
      ) {
        return match;
      }

      return attribute + '="' + proxyUrl(absolute) + '"';
    }
  );

  output = output.replace(
    /url\(\s*["']?([^)"']+)["']?\s*\)/gi,
    function (match, value) {
      if (
        value.startsWith("data:") ||
        value.startsWith("#") ||
        value.startsWith("http://") ||
        value.startsWith("https://")
      ) {
        return match;
      }

      const absolute = absoluteUrl(value, baseUrl);

      if (!absolute) {
        return match;
      }

      return "url(" + proxyUrl(absolute) + ")";
    }
  );

  output = output.replace(
    /<meta[^>]+http-equiv=["']Content-Security-Policy["'][^>]*>/gi,
    ""
  );

  return output;
}

/* =========================================================
   PROXY
   ========================================================= */

app.all("/proxy", async function (req, res) {
  if (PROXY_KEY) {
    const suppliedKey = req.headers["x-proxy-key"];

    if (suppliedKey !== PROXY_KEY) {
      return res.status(401).json({
        error: "Unauthorized"
      });
    }
  }

  const rawUrl = req.query.url;

  if (!rawUrl || typeof rawUrl !== "string") {
    return res.status(400).json({
      error: "Missing url parameter",
      example: "/proxy?url=https://example.com"
    });
  }

  let target;

  try {
    target = new URL(rawUrl);
  } catch {
    return res.status(400).json({
      error: "Invalid URL"
    });
  }

  try {
    const addresses = await validateTarget(target);
    const session = getSession(req, res);

    const headers = {};

    const allowedRequestHeaders = [
      "accept",
      "accept-language",
      "content-type",
      "referer",
      "user-agent",
      "origin"
    ];

    for (const headerName of allowedRequestHeaders) {
      const value = req.headers[headerName];

      if (value) {
        headers[headerName] = value;
      }
    }

    headers["user-agent"] =
      headers["user-agent"] ||
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131 Safari/537.36";

    const cookieHeader = getCookieHeader(session);

    if (cookieHeader) {
      headers["cookie"] = cookieHeader;
    }

    let body = null;

    if (req.method !== "GET" && req.method !== "HEAD") {
      if (Buffer.isBuffer(req.body)) {
        body = req.body;
      } else if (typeof req.body === "string") {
        body = Buffer.from(req.body);
      } else if (req.body && typeof req.body === "object") {
        if (
          req.headers["content-type"] &&
          String(req.headers["content-type"]).includes(
            "application/json"
          )
        ) {
          body = Buffer.from(JSON.stringify(req.body));
        } else {
          body = Buffer.from(new URLSearchParams(req.body).toString());
        }
      }
    }

    const upstream = await requestTarget(
      target,
      req.method,
      headers,
      body,
      addresses
    );

    saveCookies(session, upstream.headers["set-cookie"]);

    const location = upstream.headers.location;

    if (
      location &&
      [301, 302, 303, 307, 308].includes(upstream.statusCode)
    ) {
      const redirectUrl = absoluteUrl(location, target.toString());

      if (redirectUrl) {
        return res.redirect(
          upstream.statusCode,
          "/proxy?url=" + encodeURIComponent(redirectUrl)
        );
      }
    }

    let responseBody = upstream.body;
    const contentType = String(
      upstream.headers["content-type"] || ""
    ).toLowerCase();

    if (contentType.includes("text/html")) {
      const text = responseBody.toString("utf8");
      const rewritten = rewriteHtml(text, target.toString());

      responseBody = Buffer.from(rewritten, "utf8");
    }

    const responseHeaders = upstream.headers;

    for (const key of Object.keys(responseHeaders)) {
      const lower = key.toLowerCase();

      if (
        lower === "content-length" ||
        lower === "content-encoding" ||
        lower === "transfer-encoding" ||
        lower === "connection" ||
        lower === "content-security-policy" ||
        lower === "x-frame-options"
      ) {
        continue;
      }

      if (lower === "set-cookie") {
        continue;
      }

      const value = responseHeaders[key];

      if (value !== undefined) {
        res.setHeader(key, value);
      }
    }

    res.status(upstream.statusCode);
    res.setHeader("X-Proxy-Upstream", target.hostname);

    res.end(responseBody);
  } catch (error) {
    console.error("Proxy error:", error);

    return res.status(502).json({
      error: "Bad gateway",
      message: error.message || "Unknown upstream error",
      target: target.toString()
    });
  }
});

/* =========================================================
   START PAGE
   ========================================================= */

app.get("/", function (req, res) {
  res.redirect("/browser");
});

app.get("/browser", function (req, res) {
  const html =
    "<!DOCTYPE html>" +
    "<html>" +
    "<head>" +
    "<meta charset=\"UTF-8\">" +
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
    "<title>XCloud Browser</title>" +
    "<style>" +
    "*{box-sizing:border-box}" +
    "body{margin:0;background:#111;color:#fff;font-family:Arial,sans-serif}" +
    ".top{height:64px;background:#1c1c1c;display:flex;align-items:center;gap:10px;padding:10px 14px;border-bottom:1px solid #333}" +
    ".logo{font-weight:700;font-size:18px;white-space:nowrap}" +
    "form{display:flex;flex:1;gap:8px}" +
    "input{flex:1;background:#292929;color:#fff;border:1px solid #444;border-radius:8px;padding:12px;font-size:15px;outline:none}" +
    "button{background:#fff;color:#111;border:0;border-radius:8px;padding:0 18px;font-weight:700;cursor:pointer}" +
    ".home{height:calc(100vh - 64px);display:flex;align-items:center;justify-content:center;text-align:center}" +
    ".box{width:min(700px,90%)}" +
    "h1{font-size:42px;margin:0 0 10px}" +
    "p{color:#aaa}" +
    ".search{margin-top:25px;height:50px}" +
    ".search button{height:50px}" +
    "</style>" +
    "</head>" +
    "<body>" +
    "<div class=\"top\">" +
    "<div class=\"logo\">XCloud Browser</div>" +
    "<form id=\"nav\">" +
    "<input id=\"address\" placeholder=\"Search DuckDuckGo or enter a URL...\" autocomplete=\"off\">" +
    "<button type=\"submit\">Go</button>" +
    "</form>" +
    "</div>" +
    "<div class=\"home\">" +
    "<div class=\"box\">" +
    "<h1>DuckDuckGo</h1>" +
    "<p>Search the web or enter a website address.</p>" +
    "<form id=\"search\" class=\"search\">" +
    "<input id=\"query\" placeholder=\"Search the web...\" autocomplete=\"off\">" +
    "<button type=\"submit\">Search</button>" +
    "</form>" +
    "</div>" +
    "</div>" +
    "<script>" +
    "function navigate(value){" +
    "value=value.trim();" +
    "if(!value)return;" +
    "let url;" +
    "if(value.startsWith('http://')||value.startsWith('https://')){" +
    "url=value;" +
    "}else if(value.includes('.')&&!value.includes(' ')){" +
    "url='https://'+value;" +
    "}else{" +
    "url='https://duckduckgo.com/?q='+encodeURIComponent(value)+'&kl=se-sv';" +
    "}" +
    "window.location.href='/proxy?url='+encodeURIComponent(url);" +
    "}" +
    "document.getElementById('nav').addEventListener('submit',function(e){" +
    "e.preventDefault();navigate(document.getElementById('address').value);" +
    "});" +
    "document.getElementById('search').addEventListener('submit',function(e){" +
    "e.preventDefault();navigate(document.getElementById('query').value);" +
    "});" +
    "</script>" +
    "</body>" +
    "</html>";

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
   NETWORK DEBUG
   ========================================================= */

app.get("/debug-network", async function (req, res) {
  const tests = [];

  async function testHost(hostname) {
    const result = {
      hostname: hostname
    };

    try {
      const addresses = await dnsPromises.lookup(hostname, {
        all: true,
        verbatim: false
      });

      result.dns = addresses;

      const target = new URL("https://" + hostname + "/");

      const start = Date.now();

      const response = await requestTarget(
        target,
        "GET",
        {
          "user-agent": "XCloud-Debug/1.0",
          "accept": "*/*"
        },
        null,
        addresses
      );

      result.status = response.statusCode;
      result.ms = Date.now() - start;
    } catch (error) {
      result.error = error.message;

      if (error.code) {
        result.code = error.code;
      }
    }

    tests.push(result);
  }

  await testHost("example.com");
  await testHost("duckduckgo.com");

  res.json({
    ok: true,
    node: process.version,
    ipv4First: true,
    tests: tests
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

app.listen(PORT, "0.0.0.0", function () {
  console.log("");
  console.log("================================");
  console.log("XCloud Web Gateway");
  console.log("================================");
  console.log("Port: " + PORT);
  console.log("Node: " + process.version);
  console.log("IPv4-first networking: enabled");
  console.log("DuckDuckGo: enabled");
  console.log("Proxy: enabled");
  console.log("================================");
  console.log("");
});
