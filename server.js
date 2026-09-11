import express from "express";
import http from "http";
import { WebSocketServer } from "ws";

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 10000;
const ACCESS_TOKEN = process.env.ACCESS_TOKEN;

app.get("/", (req, res) => {
  res.type("html").send(`
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Gateway WebSocket Test</title>
</head>
<body>
  <h1>Gateway WebSocket Test</h1>

  <p>HTTP: <strong>working</strong></p>
  <p id="status">Testing WebSocket...</p>
  <pre id="output"></pre>

  <script>
    const output = document.getElementById("output");
    const status = document.getElementById("status");

    const wsProtocol =
      location.protocol === "https:" ? "wss:" : "ws:";

    const socket = new WebSocket(
      wsProtocol + "//" + location.host + "/ws"
    );

    socket.onopen = () => {
      status.textContent = "WebSocket: connected";
      socket.send("Hello from Chromebook");
    };

    socket.onmessage = (event) => {
      output.textContent += event.data + "\\n";
    };

    socket.onerror = () => {
      status.textContent = "WebSocket: error";
    };

    socket.onclose = () => {
      status.textContent += " / closed";
    };
  </script>
</body>
</html>
  `);
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "xcloud-test-proxy",
    websocket: true
  });
});

const wss = new WebSocketServer({
  server,
  path: "/ws"
});

wss.on("connection", (socket) => {
  console.log("WebSocket client connected");

  socket.send("WebSocket connection reached Render");

  socket.on("message", (message) => {
    console.log("Received:", message.toString());

    socket.send(
      "Render received: " + message.toString()
    );
  });

  socket.on("close", () => {
    console.log("WebSocket client disconnected");
  });
});

server.listen(PORT, "0.0.0.0", () => {
  console.log(`Server listening on port ${PORT}`);
});
