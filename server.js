import express from "express";

const app = express();

const PORT = process.env.PORT || 10000;
const ACCESS_TOKEN = process.env.ACCESS_TOKEN;

// These are the only destinations this gateway is allowed to contact.
const ALLOWED_HOSTS = new Set([
  "xbox.com",
  "www.xbox.com",
  "account.xbox.com",
  "login.live.com",
  "user.auth.xboxlive.com",
  "xsts.auth.xboxlive.com",
  "title.auth.xboxlive.com"
]);

function isAllowedHost(hostname) {
  return ALLOWED_HOSTS.has(hostname.toLowerCase());
}

function checkToken(req) {
  if (!ACCESS_TOKEN) {
    return false;
  }

  const supplied =
    req.query.token ||
    req.get("x-gateway-token") ||
    "";

  return supplied === ACCESS_TOKEN;
}

// Simple home page
app.get("/", (req, res) => {
  res.type("html").send(`
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Xbox Gateway</title>
</head>
<body>
  <h1>Xbox Gateway</h1>
  <p>The gateway is running.</p>
  <p>This is a restricted diagnostic gateway.</p>
</body>
</html>
  `);
});

// Health check
app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "xcloud-test-proxy"
  });
});

// Fetch an approved URL
app.get("/fetch", async (req, res) => {
  // Require our secret token.
  if (!checkToken(req)) {
    return res.status(401).json({
      error: "Unauthorized"
    });
  }

  const rawUrl = req.query.url;

  if (typeof rawUrl !== "string" || !rawUrl) {
    return res.status(400).json({
      error: "Missing url parameter"
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

  // Only HTTP/HTTPS.
  if (!["http:", "https:"].includes(target.protocol)) {
    return res.status(400).json({
      error: "Only HTTP and HTTPS URLs are allowed"
    });
  }

  // Prevent arbitrary-site proxying.
  if (!isAllowedHost(target.hostname)) {
    return res.status(403).json({
      error: "Host is not allowed",
      host: target.hostname
    });
  }

  try {
    const response = await fetch(target, {
      redirect: "manual",
      headers: {
        "User-Agent":
          "Mozilla/5.0 (X11; CrOS x86_64) AppleWebKit/537.36 Chrome/140 Safari/537.36",
        "Accept":
          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
      }
    });

    // Handle redirects safely.
    if (
      response.status >= 300 &&
      response.status < 400 &&
      response.headers.get("location")
    ) {
      const location = new URL(
        response.headers.get("location"),
        target
      );

      if (!isAllowedHost(location.hostname)) {
        return res.status(403).json({
          error: "Redirect destination is not allowed",
          host: location.hostname
        });
      }

      const gatewayUrl =
        `${req.protocol}://${req.get("host")}/fetch` +
        `?token=${encodeURIComponent(ACCESS_TOKEN)}` +
        `&url=${encodeURIComponent(location.toString())}`;

      return res.redirect(302, gatewayUrl);
    }

    const contentType =
      response.headers.get("content-type") ||
      "application/octet-stream";

    res.status(response.status);
    res.set("Content-Type", contentType);

    const body = Buffer.from(await response.arrayBuffer());

    res.send(body);

  } catch (error) {
    console.error(error);

    res.status(502).json({
      error: "Could not contact upstream server",
      message: error instanceof Error
        ? error.message
        : String(error)
    });
  }
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Gateway listening on port ${PORT}`);
});
