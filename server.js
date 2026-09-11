import express from "express";
import http from "http";
import crypto from "crypto";
import { WebSocketServer } from "ws";

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 10000;

app.use(express.json());

function makeSessionId() {
  return crypto.randomBytes(16).toString("hex");
}

// --------------------------------------------------
// LOGIN
// --------------------------------------------------

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
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Gateway Session Test</title>
</head>
<body>
  <h1>Test login</h1>

  <p>Session cookie created.</p>

  <p>
    <a href="/session">Continue to session test</a>
  </p>
</body>
</html>
  `);
});

// --------------------------------------------------
// SESSION/API TEST
// --------------------------------------------------

app.get("/session", (req, res) => {
  const session = req.headers.cookie || "";

  if (!session.includes("test_session=")) {
    return res.status(401).send("No session cookie found.");
  }

  res.type("html").send(`
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Streaming Test</title>
</head>
<body>

<h1>Streaming Session Test</h1>

<p id="cookie">Checking cookie...</p>
<p id="api">Checking API...</p>
<p id="socket">Connecting WebSocket...</p>
<p id="stream">Waiting for stream...</p>

<pre id="log"></pre>

<script>
const log = document.getElementById("log");

function write(message) {
  log.textContent += message + "\\n";
}

// Test authenticated API request.
fetch("/api/session")
  .then(async response => {
    const data = await response.json();

    if (response.ok) {
      document.getElementById("api").textContent =
        "API: working";
      write(JSON.stringify(data, null, 2));
    } else {
      document.getElementById("api").textContent =
        "API: failed";
    }
  })
  .catch(error => {
    document.getElementById("api").textContent =
      "API: error";
    write(error.toString());
  });

// Test WebSocket.
const protocol =
  location.protocol === "https:" ? "wss:" : "ws:";

const socket = new WebSocket(
  protocol + "//" + location.host + "/stream"
);

socket.binaryType = "arraybuffer";

socket.onopen = () => {
  document.getElementById("socket").textContent =
    "WebSocket: connected";

  write("WebSocket connected.");

  socket.send(JSON.stringify({
    type: "start-stream"
  }));
};

socket.onmessage = event => {

  if (typeof event.data === "string") {
    write("Server: " + event.data);
    return;
  }

  const bytes = new Uint8Array(event.data);

  document.getElementById("stream").textContent =
    "Binary stream: receiving";

  write(
    "Received binary packet: " +
    bytes.length +
    " bytes"
  );
};

socket.onerror = () => {
  document.getElementById("socket").textContent =
    "WebSocket: error";
};

socket.onclose = () => {
  document.getElementById("socket").textContent =
    "WebSocket: closed";
};
</script>

</body>
</html>
  `);
});

// --------------------------------------------------
// API
// --------------------------------------------------

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

// --------------------------------------------------
// WEBSOCKET STREAM
// --------------------------------------------------

const wss = new WebSocketServer({
  server,
  path: "/stream"
});

wss.on("connection", socket => {
  console.log("Streaming client connected");

  socket.send(
    JSON.stringify({
      type: "connected",
      message: "Streaming session established"
    })
  );

  let packetNumber = 0;

  const interval = setInterval(() => {
    if (socket.readyState !== 1) {
      clearInterval(interval);
      return;
    }

    packetNumber++;

    // Simulate binary streaming data.
    const packet = Buffer.alloc(1024);

    packet.writeUInt32BE(packetNumber, 0);

    for (let i = 4; i < packet.length; i++) {
      packet[i] = (packetNumber + i) % 256;
    }

    socket.send(packet);

    // Stop after 30 packets.
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
    console.log("Streaming client disconnected");
  });
});

// --------------------------------------------------
// HEALTH
// --------------------------------------------------

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    http: true,
    websocket: true,
    streaming: true
  });
});

// --------------------------------------------------
// START
// --------------------------------------------------

server.listen(PORT, "0.0.0.0", () => {
  console.log(
    `Test gateway listening on port ${PORT}`
  );
});
