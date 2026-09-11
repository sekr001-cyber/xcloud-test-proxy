import express from "express";
import path from "path";
import dns from "dns";
import net from "net";
import crypto from "crypto";
import { fileURLToPath } from "url";
import { WebSocketServer } from "ws";

const app = express();

const PORT = process.env.PORT || 10000;
const HOST = "0.0.0.0";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PUBLIC_DIR = path.join(__dirname, "public");
const GAMES_DIR = path.join(PUBLIC_DIR, "games");

// =========================================================
// EXPRESS
// =========================================================

app.disable("x-powered-by");

app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));

app.use(express.static(PUBLIC_DIR));

app.use(
  "/games",
  express.static(GAMES_DIR, {
    index: "index.html"
  })
);

app.get("/games", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

app.get("/games/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

// =========================================================
// HEALTH
// =========================================================

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "XCloud",
    multiplayer: true,
    lobbies: lobbies.size,
    time: new Date().toISOString()
  });
});

// =========================================================
// NETWORK DEBUG
// =========================================================

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

// =========================================================
// SSRF PROTECTION
// =========================================================

function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);

  if (
    parts.length !== 4 ||
    parts.some(Number.isNaN)
  ) {
    return false;
  }

  const [a, b] = parts;

  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 0) return true;

  return false;
}

function isPrivateIPv6(ip) {
  const normalized = ip.toLowerCase();

  if (normalized === "::1") return true;
  if (normalized === "::") return true;

  if (
    normalized.startsWith("fc") ||
    normalized.startsWith("fd")
  ) {
    return true;
  }

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

  if (
    lower === "localhost" ||
    lower.endsWith(".localhost") ||
    lower === "local"
  ) {
    throw new Error("Blocked hostname");
  }

  const addresses = await dns.promises.lookup(
    hostname,
    {
      all: true,
      verbatim: false
    }
  );

  if (!addresses.length) {
    throw new Error(
      "Could not resolve hostname"
    );
  }

  for (const item of addresses) {
    if (isPrivateAddress(item.address)) {
      throw new Error(
        "Target resolves to a private address"
      );
    }
  }

  return addresses;
}

// =========================================================
// COOKIE STORAGE
// =========================================================

const sessions = new Map();

function getSession(req) {
  let sessionId =
    req.headers["x-xcloud-session"];

  if (
    !sessionId ||
    typeof sessionId !== "string"
  ) {
    sessionId =
      crypto.randomBytes(18).toString("hex");
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

setInterval(() => {
  const now = Date.now();

  for (const [id, session] of sessions) {
    if (
      now - session.created >
      1000 * 60 * 60 * 6
    ) {
      sessions.delete(id);
    }
  }
}, 1000 * 60 * 30);

// =========================================================
// COOKIE HELPERS
// =========================================================

function parseSetCookie(cookieString) {
  if (!cookieString) return null;

  const firstPart =
    cookieString.split(";")[0];

  const separator =
    firstPart.indexOf("=");

  if (separator === -1) return null;

  const name =
    firstPart
      .slice(0, separator)
      .trim();

  const value =
    firstPart
      .slice(separator + 1)
      .trim();

  if (!name) return null;

  return {
    name,
    value
  };
}

function storeCookies(
  session,
  response
) {
  const cookies =
    response.headers.getSetCookie
      ? response.headers.getSetCookie()
      : [];

  for (const cookie of cookies) {
    const parsed =
      parseSetCookie(cookie);

    if (!parsed) continue;

    if (parsed.value === "") {
      session.cookies.delete(
        parsed.name
      );
    } else {
      session.cookies.set(
        parsed.name,
        parsed.value
      );
    }
  }
}

function buildCookieHeader(session) {
  return Array.from(
    session.cookies.entries()
  )
    .map(
      ([name, value]) =>
        `${name}=${value}`
    )
    .join("; ");
}

// =========================================================
// URL HELPERS
// =========================================================

function normalizeUrl(input) {
  if (!input) {
    throw new Error(
      "Missing URL"
    );
  }

  let value = input.trim();

  if (
    !/^https?:\/\//i.test(value)
  ) {
    value =
      "https://" + value;
  }

  const url = new URL(value);

  if (
    !["http:", "https:"].includes(
      url.protocol
    )
  ) {
    throw new Error(
      "Only HTTP and HTTPS are supported"
    );
  }

  return url;
}

// =========================================================
// HTML REWRITE
// =========================================================

function rewriteHtml(
  html,
  baseUrl
) {
  const base =
    new URL(baseUrl);

  html = html.replace(
    /\b(href|src|action|poster)=("([^"]*)"|'([^']*)')/gi,
    (
      match,
      attribute,
      quotedValue,
      doubleValue,
      singleValue
    ) => {
      const value =
        doubleValue ??
        singleValue;

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
        const absolute =
          new URL(
            value,
            base
          ).href;

        return `${attribute}="/proxy?url=${encodeURIComponent(
          absolute
        )}"`;
      } catch {
        return match;
      }
    }
  );

  return html;
}

// =========================================================
// PROXY
// =========================================================

app.all(
  "/proxy",
  async (req, res) => {
    let targetUrl;

    try {
      targetUrl =
        normalizeUrl(
          req.query.url
        );
    } catch (error) {
      return res.status(400).json({
        ok: false,
        error: error.message
      });
    }

    try {
      await validateTarget(
        targetUrl.hostname
      );
    } catch (error) {
      return res.status(403).json({
        ok: false,
        error: error.message
      });
    }

    const {
      id: sessionId,
      data: session
    } = getSession(req);

    const controller =
      new AbortController();

    const timeout =
      setTimeout(
        () => controller.abort(),
        20000
      );

    try {
      const headers = {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131 Safari/537.36",
        "Accept":
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language":
          req.headers[
            "accept-language"
          ] ||
          "en-US,en;q=0.9",
        "Cache-Control":
          "no-cache"
      };

      const cookieHeader =
        buildCookieHeader(
          session
        );

      if (cookieHeader) {
        headers.Cookie =
          cookieHeader;
      }

      if (
        req.headers[
          "content-type"
        ]
      ) {
        headers[
          "Content-Type"
        ] =
          req.headers[
            "content-type"
          ];
      }

      let body;

      if (
        !["GET", "HEAD"].includes(
          req.method
        )
      ) {
        if (
          typeof req.body ===
            "object" &&
          req.body !== null
        ) {
          body =
            JSON.stringify(
              req.body
            );

          headers[
            "Content-Type"
          ] =
            headers[
              "Content-Type"
            ] ||
            "application/json";
        }
      }

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
              controller.signal
          }
        );

      storeCookies(
        session,
        response
      );

      if (
        response.status >= 300 &&
        response.status < 400 &&
        response.headers.get(
          "location"
        )
      ) {
        const location =
          new URL(
            response.headers.get(
              "location"
            ),
            targetUrl
          );

        return res.redirect(
          response.status,
          "/proxy?url=" +
            encodeURIComponent(
              location.href
            )
        );
      }

      const contentType =
        response.headers.get(
          "content-type"
        ) ||
        "application/octet-stream";

      res.setHeader(
        "X-XCloud-Session",
        sessionId
      );

      const forwardHeaders = [
        "content-type",
        "content-language",
        "cache-control",
        "etag",
        "last-modified",
        "content-disposition"
      ];

      for (
        const header of forwardHeaders
      ) {
        const value =
          response.headers.get(
            header
          );

        if (value) {
          res.setHeader(
            header,
            value
          );
        }
      }

      if (
        contentType.includes(
          "text/html"
        ) ||
        contentType.includes(
          "application/xhtml+xml"
        )
      ) {
        const text =
          await response.text();

        return res
          .status(
            response.status
          )
          .send(
            rewriteHtml(
              text,
              targetUrl.href
            )
          );
      }

      const arrayBuffer =
        await response.arrayBuffer();

      return res
        .status(
          response.status
        )
        .send(
          Buffer.from(
            arrayBuffer
          )
        );
    } catch (error) {
      console.error(
        "Proxy error:",
        error
      );

      if (
        error.name ===
        "AbortError"
      ) {
        return res
          .status(504)
          .json({
            ok: false,
            error:
              "Target request timed out"
          });
      }

      return res
        .status(502)
        .json({
          ok: false,
          error:
            "Proxy request failed",
          details:
            error.message
        });
    } finally {
      clearTimeout(
        timeout
      );
    }
  }
);

// =========================================================
// MULTIPLAYER
// =========================================================

const lobbies = new Map();

const MAPS = [
  "Sunset Circuit",
  "City Rush",
  "Desert Run",
  "Snow Valley",
  "Neon Tokyo"
];

const MAX_PLAYERS = 8;

function createLobbyCode() {
  const chars =
    "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

  let code = "";

  do {
    code = "";

    for (
      let i = 0;
      i < 6;
      i++
    ) {
      code +=
        chars[
          Math.floor(
            Math.random() *
              chars.length
          )
        ];
    }
  } while (
    lobbies.has(code)
  );

  return code;
}

function createPlayerId() {
  return crypto
    .randomBytes(8)
    .toString("hex");
}

function send(ws, type, data = {}) {
  if (
    ws &&
    ws.readyState ===
      ws.OPEN
  ) {
    ws.send(
      JSON.stringify({
        type,
        ...data
      })
    );
  }
}

function broadcast(
  lobby,
  type,
  data = {}
) {
  for (
    const player of lobby.players.values()
  ) {
    send(
      player.ws,
      type,
      data
    );
  }
}

function lobbyState(lobby) {
  return {
    code: lobby.code,
    hostId: lobby.hostId,
    status: lobby.status,
    map: lobby.map,
    laps: lobby.laps,
    aiCount: lobby.aiCount,

    players:
      Array.from(
        lobby.players.values()
      ).map(
        player => ({
          id: player.id,
          name: player.name,
          ready: player.ready,
          car: player.car
        })
      )
  };
}

function broadcastLobby(
  lobby
) {
  broadcast(
    lobby,
    "lobby_update",
    {
      lobby:
        lobbyState(lobby)
    }
  );
}

function removePlayer(
  player
) {
  if (!player.lobby) {
    return;
  }

  const lobby =
    player.lobby;

  lobby.players.delete(
    player.id
  );

  player.lobby = null;

  if (
    lobby.players.size ===
    0
  ) {
    lobbies.delete(
      lobby.code
    );

    return;
  }

  if (
    lobby.hostId ===
    player.id
  ) {
    const nextHost =
      lobby.players.values()
        .next()
        .value;

    lobby.hostId =
      nextHost.id;
  }

  broadcastLobby(
    lobby
  );
}

// =========================================================
// WEBSOCKET SERVER
// =========================================================

const httpServer =
  app.listen(
    PORT,
    HOST,
    () => {
      console.log(
        "======================================"
      );

      console.log(
        "       XCLOUD SERVER ONLINE"
      );

      console.log(
        "======================================"
      );

      console.log(
        `Port: ${PORT}`
      );

      console.log(
        `Public: ${PUBLIC_DIR}`
      );

      console.log(
        `Games: ${GAMES_DIR}`
      );

      console.log(
        "Multiplayer: ENABLED"
      );

      console.log(
        "======================================"
      );
    }
  );

const wss =
  new WebSocketServer({
    server:
      httpServer,
    path:
      "/ws"
  });

wss.on(
  "connection",
  ws => {
    const player = {
      id:
        createPlayerId(),

      ws,

      name:
        "Player",

      car:
        "red",

      ready:
        false,

      lobby:
        null,

      lastState:
        null
    };

    send(
      ws,
      "connected",
      {
        playerId:
          player.id
      }
    );

    ws.on(
      "message",
      raw => {
        let message;

        try {
          message =
            JSON.parse(
              raw.toString()
            );
        } catch {
          send(
            ws,
            "error",
            {
              message:
                "Invalid message"
            }
          );

          return;
        }

        handleMessage(
          player,
          message
        );
      }
    );

    ws.on(
      "close",
      () => {
        removePlayer(
          player
        );
      }
    );

    ws.on(
      "error",
      () => {
        removePlayer(
          player
        );
      }
    );
  }
);

// =========================================================
// WEBSOCKET MESSAGE HANDLER
// =========================================================

function handleMessage(
  player,
  message
) {
  switch (
    message.type
  ) {
    case "set_profile":
      handleProfile(
        player,
        message
      );
      break;

    case "create_lobby":
      handleCreateLobby(
        player,
        message
      );
      break;

    case "join_lobby":
      handleJoinLobby(
        player,
        message
      );
      break;

    case "leave_lobby":
      removePlayer(
        player
      );
      break;

    case "ready":
      handleReady(
        player
      );
      break;

    case "set_map":
      handleSetMap(
        player,
        message
      );
      break;

    case "set_ai":
      handleSetAI(
        player,
        message
      );
      break;

    case "start_race":
      handleStartRace(
        player
      );
      break;

    case "race_state":
      handleRaceState(
        player,
        message
      );
      break;

    default:
      send(
        player.ws,
        "error",
        {
          message:
            "Unknown command"
        }
      );
  }
}

// =========================================================
// PROFILE
// =========================================================

function handleProfile(
  player,
  message
) {
  if (
    typeof message.name ===
    "string"
  ) {
    const name =
      message.name
        .trim()
        .slice(0, 16);

    if (name.length > 0) {
      player.name =
        name;
    }
  }

  if (
    typeof message.car ===
    "string"
  ) {
    player.car =
      message.car
        .slice(0, 30);
  }

  if (player.lobby) {
    broadcastLobby(
      player.lobby
    );
  }
}

// =========================================================
// CREATE LOBBY
// =========================================================

function handleCreateLobby(
  player,
  message
) {
  if (player.lobby) {
    send(
      player.ws,
      "error",
      {
        message:
          "You are already in a lobby."
      }
    );

    return;
  }

  const code =
    createLobbyCode();

  const lobby = {
    code,

    hostId:
      player.id,

    status:
      "waiting",

    map:
      MAPS.includes(
        message.map
      )
        ? message.map
        : MAPS[0],

    laps:
      Number.isInteger(
        message.laps
      )
        ? Math.max(
            1,
            Math.min(
              9,
              message.laps
            )
          )
        : 3,

    aiCount:
      Number.isInteger(
        message.aiCount
      )
        ? Math.max(
            0,
            Math.min(
              7,
              message.aiCount
            )
          )
        : 7,

    players:
      new Map(),

    created:
      Date.now()
  };

  lobbies.set(
    code,
    lobby
  );

  player.lobby =
    lobby;

  player.ready =
    true;

  lobby.players.set(
    player.id,
    player
  );

  send(
    player.ws,
    "lobby_created",
    {
      lobby:
        lobbyState(lobby)
    }
  );

  broadcastLobby(
    lobby
  );
}

// =========================================================
// JOIN
// =========================================================

function handleJoinLobby(
  player,
  message
) {
  if (player.lobby) {
    send(
      player.ws,
      "error",
      {
        message:
          "You are already in a lobby."
      }
    );

    return;
  }

  const code =
    String(
      message.code || ""
    )
      .trim()
      .toUpperCase();

  const lobby =
    lobbies.get(code);

  if (!lobby) {
    send(
      player.ws,
      "error",
      {
        message:
          "Lobby not found."
      }
    );

    return;
  }

  if (
    lobby.status !==
    "waiting"
  ) {
    send(
      player.ws,
      "error",
      {
        message:
          "This race has already started."
      }
    );

    return;
  }

  if (
    lobby.players.size >=
    MAX_PLAYERS
  ) {
    send(
      player.ws,
      "error",
      {
        message:
          "Lobby is full."
      }
    );

    return;
  }

  player.lobby =
    lobby;

  player.ready =
    false;

  lobby.players.set(
    player.id,
    player
  );

  send(
    player.ws,
    "lobby_joined",
    {
      lobby:
        lobbyState(lobby)
    }
  );

  broadcastLobby(
    lobby
  );
}

// =========================================================
// READY
// =========================================================

function handleReady(
  player
) {
  if (!player.lobby) {
    return;
  }

  if (
    player.lobby.status !==
    "waiting"
  ) {
    return;
  }

  player.ready =
    !player.ready;

  broadcastLobby(
    player.lobby
  );
}

// =========================================================
// MAP
// =========================================================

function handleSetMap(
  player,
  message
) {
  const lobby =
    player.lobby;

  if (!lobby) return;

  if (
    lobby.hostId !==
    player.id
  ) {
    return;
  }

  if (
    lobby.status !==
    "waiting"
  ) {
    return;
  }

  if (
    MAPS.includes(
      message.map
    )
  ) {
    lobby.map =
      message.map;
  }

  broadcastLobby(
    lobby
  );
}

// =========================================================
// AI
// =========================================================

function handleSetAI(
  player,
  message
) {
  const lobby =
    player.lobby;

  if (!lobby) return;

  if (
    lobby.hostId !==
    player.id
  ) {
    return;
  }

  if (
    lobby.status !==
    "waiting"
  ) {
    return;
  }

  const count =
    Number(
      message.count
    );

  if (
    Number.isFinite(
      count
    )
  ) {
    lobby.aiCount =
      Math.max(
        0,
        Math.min(
          7,
          Math.round(count)
        )
      );
  }

  broadcastLobby(
    lobby
  );
}

// =========================================================
// START RACE
// =========================================================

function handleStartRace(
  player
) {
  const lobby =
    player.lobby;

  if (!lobby) {
    return;
  }

  if (
    lobby.hostId !==
    player.id
  ) {
    send(
      player.ws,
      "error",
      {
        message:
          "Only the host can start the race."
      }
    );

    return;
  }

  if (
    lobby.status !==
    "waiting"
  ) {
    return;
  }

  const everyoneReady =
    Array.from(
      lobby.players.values()
    ).every(
      p => p.ready
    );

  if (!everyoneReady) {
    send(
      player.ws,
      "error",
      {
        message:
          "Everyone must be ready."
      }
    );

    return;
  }

  lobby.status =
    "countdown";

  broadcast(
    lobby,
    "race_countdown",
    {
      seconds: 3,
      map: lobby.map,
      laps: lobby.laps,
      aiCount:
        lobby.aiCount
    }
  );

  setTimeout(() => {
    if (
      !lobbies.has(
        lobby.code
      )
    ) {
      return;
    }

    lobby.status =
      "racing";

    broadcast(
      lobby,
      "race_start",
      {
        map: lobby.map,
        laps: lobby.laps,
        aiCount:
          lobby.aiCount
      }
    );
  }, 3500);
}

// =========================================================
// RACE STATE
// =========================================================

function handleRaceState(
  player,
  message
) {
  const lobby =
    player.lobby;

  if (!lobby) {
    return;
  }

  if (
    lobby.status !==
    "racing"
  ) {
    return;
  }

  if (
    !message.state
  ) {
    return;
  }

  player.lastState = {
    x:
      Number(
        message.state.x
      ) || 0,

    y:
      Number(
        message.state.y
      ) || 0,

    angle:
      Number(
        message.state.angle
      ) || 0,

    speed:
      Number(
        message.state.speed
      ) || 0,

    lap:
      Number(
        message.state.lap
      ) || 1,

    position:
      Number(
        message.state.position
      ) || 1
  };

  for (
    const other of
      lobby.players.values()
  ) {
    if (
      other.id ===
      player.id
    ) {
      continue;
    }

    if (
      !other.lastState
    ) {
      continue;
    }

    send(
      player.ws,
      "player_state",
      {
        playerId:
          other.id,

        state:
          other.lastState
      }
    );
  }
}

// =========================================================
// CLEANUP OLD LOBBIES
// =========================================================

setInterval(() => {
  const now =
    Date.now();

  for (
    const [
      code,
      lobby
    ] of lobbies
  ) {
    if (
      now -
        lobby.created >
      1000 * 60 * 60
    ) {
      broadcast(
        lobby,
        "error",
        {
          message:
            "Lobby expired."
        }
      );

      for (
        const player of
          lobby.players.values()
      ) {
        try {
          player.ws.close();
        } catch {}
      }

      lobbies.delete(
        code
      );
    }
  }
}, 1000 * 60 * 5);

// =========================================================
// WEBSOCKET HEARTBEAT
// =========================================================

setInterval(() => {
  for (
    const ws of wss.clients
  ) {
    if (
      ws.readyState ===
      ws.OPEN
    ) {
      ws.ping();
    }
  }
}, 30000);

// =========================================================
// 404
// =========================================================

app.use(
  (req, res) => {
    if (
      req.accepts("html")
    ) {
      return res
        .status(404)
        .send(`
          <!DOCTYPE html>
          <html>
          <head>
            <meta charset="UTF-8">
            <title>XCloud - 404</title>
            <style>
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
  }
);
