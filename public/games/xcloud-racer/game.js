const canvas = document.getElementById("game");
const ctx = canvas.getContext("2d");

const startScreen = document.getElementById("startScreen");
const finishScreen = document.getElementById("finishScreen");
const countdownElement = document.getElementById("countdown");

const positionElement = document.getElementById("position");
const lapElement = document.getElementById("lap");
const speedElement = document.getElementById("speed");
const timeElement = document.getElementById("time");
const boostFill = document.getElementById("boostFill");

let width = 0;
let height = 0;

let running = false;
let raceFinished = false;

let raceStartTime = 0;
let finishTime = 0;

const TOTAL_LAPS = 3;

let keys = {};

const camera = {
  x: 0,
  y: 0
};

const player = {
  x: 0,
  y: 0,

  angle: 0,

  speed: 0,
  maxSpeed: 430,

  acceleration: 300,
  braking: 420,

  turnSpeed: 2.9,

  width: 30,
  height: 52,

  boost: 100,

  lap: 1,
  checkpoint: 0,

  distance: 0,

  color: "#ff3d3d"
};

/* =========================================================
   TRACK
   ========================================================= */

const track = [
  { x: 0, y: -700 },
  { x: 500, y: -650 },
  { x: 850, y: -350 },
  { x: 900, y: 100 },
  { x: 700, y: 500 },
  { x: 250, y: 700 },
  { x: -250, y: 650 },
  { x: -700, y: 450 },
  { x: -900, y: 0 },
  { x: -800, y: -450 },
  { x: -400, y: -650 }
];

const TRACK_WIDTH = 260;

/* =========================================================
   AI
   ========================================================= */

const aiCars = [];

const aiColors = [
  "#3498db",
  "#f1c40f",
  "#9b59b6",
  "#2ecc71",
  "#e67e22",
  "#00cec9",
  "#ff7675"
];

function createAI(index) {
  const point = track[index % track.length];

  return {
    x: point.x + (index % 2 === 0 ? -35 : 35),
    y: point.y + 30,

    angle: 0,

    speed: 220 + Math.random() * 70,

    targetSpeed:
      270 + Math.random() * 100,

    width: 30,
    height: 52,

    color:
      aiColors[index % aiColors.length],

    waypoint:
      index % track.length,

    progress:
      index * -25,

    lap: 1,

    skill:
      0.8 + Math.random() * 0.3,

    wobble:
      Math.random() * 100,

    finished: false
  };
}

for (let i = 0; i < 7; i++) {
  aiCars.push(createAI(i));
}

/* =========================================================
   RESIZE
   ========================================================= */

function resize() {
  width = window.innerWidth;
  height = window.innerHeight;

  const ratio = window.devicePixelRatio || 1;

  canvas.width = width * ratio;
  canvas.height = height * ratio;

  canvas.style.width = width + "px";
  canvas.style.height = height + "px";

  ctx.setTransform(
    ratio,
    0,
    0,
    ratio,
    0,
    0
  );
}

window.addEventListener(
  "resize",
  resize
);

resize();

/* =========================================================
   INPUT
   ========================================================= */

window.addEventListener(
  "keydown",
  function (event) {
    keys[event.key.toLowerCase()] = true;

    if (
      [
        "arrowup",
        "arrowdown",
        "arrowleft",
        "arrowright",
        " "
      ].includes(event.key.toLowerCase())
    ) {
      event.preventDefault();
    }
  }
);

window.addEventListener(
  "keyup",
  function (event) {
    keys[event.key.toLowerCase()] = false;
  }
);

/* =========================================================
   START
   ========================================================= */

document
  .getElementById("startButton")
  .addEventListener(
    "click",
    startRace
  );

document
  .getElementById("restartButton")
  .addEventListener(
    "click",
    function () {
      location.reload();
    }
  );

function resetPlayer() {
  player.x = 0;
  player.y = -520;

  player.angle = 0;

  player.speed = 0;

  player.boost = 100;

  player.lap = 1;
  player.checkpoint = 0;

  player.distance = 0;
}

function resetAI() {
  aiCars.length = 0;

  for (let i = 0; i < 7; i++) {
    aiCars.push(createAI(i));
  }
}

function startRace() {
  resetPlayer();
  resetAI();

  startScreen.style.display = "none";

  raceFinished = false;

  runCountdown();
}

function runCountdown() {
  const numbers = [
    "3",
    "2",
    "1",
    "GO!"
  ];

  let index = 0;

  countdownElement.style.opacity = "1";

  const interval =
    setInterval(function () {
      countdownElement.textContent =
        numbers[index];

      index++;

      if (index >= numbers.length) {
        clearInterval(interval);

        setTimeout(function () {
          countdownElement.style.opacity =
            "0";

          running = true;

          raceStartTime =
            performance.now();
        }, 500);
      }
    }, 900);
}

/* =========================================================
   TRACK MATH
   ========================================================= */

function distance(a, b) {
  const dx = a.x - b.x;
  const dy = a.y - b.y;

  return Math.sqrt(
    dx * dx + dy * dy
  );
}

function nearestTrackPoint(x, y) {
  let closest = track[0];
  let closestDistance = Infinity;
  let closestIndex = 0;

  for (let i = 0; i < track.length; i++) {
    const d = distance(
      { x, y },
      track[i]
    );

    if (d < closestDistance) {
      closestDistance = d;
      closest = track[i];
      closestIndex = i;
    }
  }

  return {
    point: closest,
    distance: closestDistance,
    index: closestIndex
  };
}

function isOnTrack(car) {
  return (
    nearestTrackPoint(
      car.x,
      car.y
    ).distance <
    TRACK_WIDTH / 2
  );
}

/* =========================================================
   PLAYER UPDATE
   ========================================================= */

function updatePlayer(dt) {
  const accelerating =
    keys["w"] ||
    keys["arrowup"];

  const braking =
    keys["s"] ||
    keys["arrowdown"];

  const left =
    keys["a"] ||
    keys["arrowleft"];

  const right =
    keys["d"] ||
    keys["arrowright"];

  const boosting =
    keys["shift"] &&
    player.boost > 0;

  let maxSpeed =
    player.maxSpeed;

  if (boosting) {
    maxSpeed *= 1.45;

    player.boost -=
      40 * dt;
  } else {
    player.boost +=
      12 * dt;
  }

  player.boost =
    Math.max(
      0,
      Math.min(
        100,
        player.boost
      )
    );

  if (accelerating) {
    player.speed +=
      player.acceleration * dt;
  } else {
    player.speed -=
      90 * dt;
  }

  if (braking) {
    player.speed -=
      player.braking * dt;
  }

  player.speed =
    Math.max(
      -100,
      Math.min(
        maxSpeed,
        player.speed
      )
    );

  const steering =
    Math.min(
      1,
      Math.abs(player.speed) /
        100
    );

  if (left) {
    player.angle -=
      player.turnSpeed *
      steering *
      dt;
  }

  if (right) {
    player.angle +=
      player.turnSpeed *
      steering *
      dt;
  }

  const previousX =
    player.x;

  const previousY =
    player.y;

  player.x +=
    Math.sin(player.angle) *
    player.speed *
    dt;

  player.y -=
    Math.cos(player.angle) *
    player.speed *
    dt;

  if (!isOnTrack(player)) {
    player.speed *=
      Math.pow(
        0.92,
        dt * 60
      );
  }

  player.distance +=
    distance(
      { x: previousX, y: previousY },
      { x: player.x, y: player.y }
    );

  updateLap();
}

/* =========================================================
   LAP SYSTEM
   ========================================================= */

function updateLap() {
  const nearest =
    nearestTrackPoint(
      player.x,
      player.y
    );

  if (
    nearest.index !==
    player.checkpoint
  ) {
    const difference =
      nearest.index -
      player.checkpoint;

    if (
      difference > 0 ||
      difference <
        -(track.length - 1)
    ) {
      player.checkpoint =
        nearest.index;
    }
  }

  if (
    player.checkpoint >=
      track.length - 2 &&
    nearest.index <= 1 &&
    player.distance > 1500
  ) {
    player.lap++;

    player.distance = 0;

    player.checkpoint = 1;

    if (
      player.lap >
      TOTAL_LAPS
    ) {
      finishRace();
    }
  }
}

/* =========================================================
   AI UPDATE
   ========================================================= */

function updateAI(car, dt) {
  if (car.finished) {
    return;
  }

  const target =
    track[car.waypoint];

  const dx =
    target.x - car.x;

  const dy =
    target.y - car.y;

  const targetAngle =
    Math.atan2(
      dx,
      -dy
    );

  let difference =
    targetAngle -
    car.angle;

  while (
    difference > Math.PI
  ) {
    difference -=
      Math.PI * 2;
  }

  while (
    difference < -Math.PI
  ) {
    difference +=
      Math.PI * 2;
  }

  const turn =
    Math.max(
      -1,
      Math.min(
        1,
        difference * 2
      )
    );

  car.angle +=
    turn *
    2.5 *
    dt *
    car.skill;

  car.speed +=
    (
      car.targetSpeed -
      car.speed
    ) *
    dt *
    1.5;

  car.speed =
    Math.max(
      100,
      Math.min(
        car.targetSpeed,
        car.speed
      )
    );

  car.x +=
    Math.sin(car.angle) *
    car.speed *
    dt;

  car.y -=
    Math.cos(car.angle) *
    car.speed *
    dt;

  const targetDistance =
    distance(
      { x: car.x, y: car.y },
      target
    );

  if (
    targetDistance <
    100
  ) {
    car.waypoint++;

    if (
      car.waypoint >=
      track.length
    ) {
      car.waypoint = 0;

      car.lap++;

      if (
        car.lap >
        TOTAL_LAPS
      ) {
        car.finished = true;
      }
    }
  }

  car.progress =
    (car.lap - 1) *
      track.length +
    car.waypoint;
}

/* =========================================================
   COLLISIONS
   ========================================================= */

function collision(a, b) {
  return (
    Math.abs(a.x - b.x) <
      35 &&
    Math.abs(a.y - b.y) <
      50
  );
}

function handleCollisions() {
  for (const car of aiCars) {
    if (
      collision(
        player,
        car
      )
    ) {
      player.speed *=
        0.55;

      const dx =
        player.x - car.x;

      const dy =
        player.y - car.y;

      const length =
        Math.sqrt(
          dx * dx +
          dy * dy
        ) || 1;

      player.x +=
        (dx / length) *
        8;

      player.y +=
        (dy / length) *
        8;
    }
  }
}

/* =========================================================
   POSITION
   ========================================================= */

function getPlayerProgress() {
  const nearest =
    nearestTrackPoint(
      player.x,
      player.y
    );

  return (
    (player.lap - 1) *
      track.length +
    nearest.index
  );
}

function updatePosition() {
  const playerProgress =
    getPlayerProgress();

  let position = 1;

  for (const car of aiCars) {
    if (
      car.progress >
      playerProgress
    ) {
      position++;
    }
  }

  positionElement.textContent =
    position + "/" +
    (aiCars.length + 1);

  lapElement.textContent =
    Math.min(
      player.lap,
      TOTAL_LAPS
    ) +
    "/" +
    TOTAL_LAPS;

  speedElement.textContent =
    Math.round(
      Math.abs(player.speed)
    );

  boostFill.style.width =
    player.boost + "%";

  if (raceStartTime) {
    const elapsed =
      (
        performance.now() -
        raceStartTime
      ) / 1000;

    timeElement.textContent =
      formatTime(elapsed);
  }
}

/* =========================================================
   FINISH
   ========================================================= */

function finishRace() {
  if (raceFinished) {
    return;
  }

  raceFinished = true;
  running = false;

  finishTime =
    performance.now() -
    raceStartTime;

  const seconds =
    finishTime / 1000;

  const position =
    Number(
      positionElement.textContent
        .split("/")[0]
    );

  document.getElementById(
    "resultPosition"
  ).textContent =
    "#" + position;

  document.getElementById(
    "resultTime"
  ).textContent =
    formatTime(seconds);

  finishScreen.classList.add(
    "show"
  );
}

function formatTime(seconds) {
  const minutes =
    Math.floor(
      seconds / 60
    );

  const remaining =
    seconds % 60;

  return (
    String(minutes).padStart(2, "0") +
    ":" +
    remaining
      .toFixed(2)
      .padStart(5, "0")
  );
}

/* =========================================================
   CAMERA
   ========================================================= */

function updateCamera() {
  camera.x +=
    (
      player.x -
      camera.x
    ) * 0.08;

  camera.y +=
    (
      player.y -
      camera.y
    ) * 0.08;
}

/* =========================================================
   DRAW TRACK
   ========================================================= */

function drawTrack() {
  ctx.save();

  ctx.translate(
    -camera.x +
      width / 2,
    -camera.y +
      height / 2
  );

  /* grass */

  ctx.fillStyle =
    "#1d4b2b";

  ctx.fillRect(
    camera.x - width,
    camera.y - height,
    width * 2,
    height * 2
  );

  /* road */

  ctx.beginPath();

  for (let i = 0; i < track.length; i++) {
    const point =
      track[i];

    if (i === 0) {
      ctx.moveTo(
        point.x,
        point.y
      );
    } else {
      ctx.lineTo(
        point.x,
        point.y
      );
    }
  }

  ctx.closePath();

  ctx.lineWidth =
    TRACK_WIDTH;

  ctx.lineCap = "round";
  ctx.lineJoin = "round";

  ctx.strokeStyle =
    "#3c4047";

  ctx.stroke();

  /* road border */

  ctx.lineWidth =
    TRACK_WIDTH + 12;

  ctx.strokeStyle =
    "#e8e8e8";

  ctx.stroke();

  ctx.lineWidth =
    TRACK_WIDTH;

  ctx.strokeStyle =
    "#3c4047";

  ctx.stroke();

  /* center line */

  ctx.setLineDash([
    30,
    25
  ]);

  ctx.lineWidth = 4;

  ctx.strokeStyle =
    "#f3d45c";

  ctx.stroke();

  ctx.setLineDash([]);

  /* start line */

  const start =
    track[0];

  ctx.save();

  ctx.translate(
    start.x,
    start.y
  );

  ctx.rotate(0);

  const square = 18;

  for (let x = -6; x <= 6; x++) {
    for (let y = -1; y <= 1; y++) {
      ctx.fillStyle =
        (x + y) % 2 === 0
          ? "#fff"
          : "#111";

      ctx.fillRect(
        x * square,
        y * square,
        square,
        square
      );
    }
  }

  ctx.restore();

  ctx.restore();
}

/* =========================================================
   DRAW CAR
   ========================================================= */

function drawCar(car, isPlayer) {
  ctx.save();

  ctx.translate(
    car.x -
      camera.x +
      width / 2,
    car.y -
      camera.y +
      height / 2
  );

  ctx.rotate(car.angle);

  const w =
    car.width;

  const h =
    car.height;

  /* shadow */

  ctx.fillStyle =
    "rgba(0,0,0,0.35)";

  ctx.fillRect(
    -w / 2 + 4,
    -h / 2 + 6,
    w,
    h
  );

  /* body */

  ctx.fillStyle =
    car.color;

  ctx.beginPath();

  ctx.roundRect(
    -w / 2,
    -h / 2,
    w,
    h,
    7
  );

  ctx.fill();

  /* windshield */

  ctx.fillStyle =
    "rgba(20,25,30,0.8)";

  ctx.beginPath();

  ctx.roundRect(
    -w * 0.34,
    -h * 0.25,
    w * 0.68,
    h * 0.25,
    4
  );

  ctx.fill();

  /* rear window */

  ctx.fillStyle =
    "rgba(20,25,30,0.65)";

  ctx.fillRect(
    -w * 0.28,
    h * 0.05,
    w * 0.56,
    h * 0.15
  );

  /* headlights */

  ctx.fillStyle =
    "#fff";

  ctx.fillRect(
    -w * 0.38,
    -h * 0.46,
    7,
    5
  );

  ctx.fillRect(
    w * 0.15,
    -h * 0.46,
    7,
    5
  );

  if (isPlayer) {
    ctx.strokeStyle =
      "#ffffff";

    ctx.lineWidth = 2;

    ctx.stroke();
  }

  ctx.restore();
}

/* =========================================================
   DRAW
   ========================================================= */

function draw() {
  ctx.clearRect(
    0,
    0,
    width,
    height
  );

  drawTrack();

  for (const car of aiCars) {
    drawCar(
      car,
      false
    );
  }

  drawCar(
    player,
    true
  );
}

/* =========================================================
   GAME LOOP
   ========================================================= */

let lastTime =
  performance.now();

function loop(now) {
  const dt =
    Math.min(
      0.033,
      (now - lastTime) /
        1000
    );

  lastTime = now;

  if (running) {
    updatePlayer(dt);

    for (const car of aiCars) {
      updateAI(
        car,
        dt
      );
    }

    handleCollisions();

    updateCamera();

    updatePosition();
  }

  draw();

  requestAnimationFrame(
    loop
  );
}

requestAnimationFrame(
  loop
);

/* =========================================================
   MOBILE CONTROLS
   ========================================================= */

function bindMobileButton(
  id,
  key
) {
  const element =
    document.getElementById(id);

  if (!element) {
    return;
  }

  function press(event) {
    event.preventDefault();

    keys[key] = true;
  }

  function release(event) {
    event.preventDefault();

    keys[key] = false;
  }

  element.addEventListener(
    "touchstart",
    press,
    { passive: false }
  );

  element.addEventListener(
    "touchend",
    release,
    { passive: false }
  );

  element.addEventListener(
    "mousedown",
    press
  );

  element.addEventListener(
    "mouseup",
    release
  );

  element.addEventListener(
    "mouseleave",
    release
  );
}

bindMobileButton(
  "mobileLeft",
  "arrowleft"
);

bindMobileButton(
  "mobileRight",
  "arrowright"
);

bindMobileButton(
  "mobileGas",
  "arrowup"
);

bindMobileButton(
  "mobileBrake",
  "arrowdown"
);
