// 실시간 생중계 추첨기 서버 (외부 라이브러리 없음, Node.js 18+)
// - public/index.html 을 보여주고
// - /ws 로 WebSocket 연결을 받아 모든 접속자에게 같은 추첨 결과를 방송합니다.
// - 당첨자는 서버에서 정합니다(진행자 화면에서 조작 불가).
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = process.env.PORT || 3000;
let HOST_KEY = process.env.HOST_KEY;
if (!HOST_KEY || HOST_KEY.length < 8) {
  HOST_KEY = crypto.randomBytes(9).toString("base64url");
  console.log("[경고] HOST_KEY 환경변수가 없어 임시 키를 만들었습니다:", HOST_KEY);
}

const TAU = Math.PI * 2;
const COUNTDOWN_MS = 3000;
const MAX_NAMES = 300;

let state = { names: [], rest: 0, spin: null, history: [], showWinner: false };
let spinTimer = null;
const clients = new Set();

// ---------- 정적 파일 (public 폴더: index.html, logo.png 등) ----------
const PUBLIC = path.join(__dirname, "public");
const TYPES = { ".html": "text/html; charset=utf-8", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
  ".svg": "image/svg+xml", ".webp": "image/webp", ".ico": "image/x-icon", ".css": "text/css", ".js": "text/javascript" };
const server = http.createServer((req, res) => {
  if (req.url === "/health") { res.writeHead(200); return res.end("ok"); }
  let p; try { p = decodeURIComponent(req.url.split("?")[0]); } catch { p = "/"; }
  if (p === "/") p = "/index.html";
  const file = path.join(PUBLIC, path.normalize(p));
  if (!file.startsWith(PUBLIC + path.sep)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); return res.end("not found"); }
    res.writeHead(200, { "Content-Type": TYPES[path.extname(file).toLowerCase()] || "application/octet-stream", "Cache-Control": "no-cache" });
    res.end(data);
  });
});

// ---------- 최소 WebSocket 구현 ----------
server.on("upgrade", (req, socket) => {
  if (!req.url.startsWith("/ws") || req.headers.upgrade?.toLowerCase() !== "websocket") return socket.destroy();
  const key = req.headers["sec-websocket-key"];
  if (!key) return socket.destroy();
  const accept = crypto.createHash("sha1").update(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
  socket.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + accept + "\r\n\r\n");
  socket.setNoDelay(true);

  const client = { socket, isHost: false, buf: Buffer.alloc(0), alive: true };
  clients.add(client);
  send(client, { t: "state", s: state });
  broadcastCount();

  socket.on("data", (chunk) => {
    client.buf = Buffer.concat([client.buf, chunk]);
    if (client.buf.length > 1e6) return socket.destroy();
    let frame;
    while ((frame = readFrame(client))) {
      if (frame.op === 8) return socket.end();
      if (frame.op === 9) { writeFrame(socket, 10, frame.data); continue; }
      if (frame.op === 1) {
        let msg; try { msg = JSON.parse(frame.data.toString("utf8")); } catch { continue; }
        if (msg && typeof msg === "object") handle(client, msg);
      }
    }
  });
  const drop = () => { if (clients.delete(client)) broadcastCount(); };
  socket.on("close", drop);
  socket.on("error", drop);
});

function readFrame(c) {
  const b = c.buf;
  if (b.length < 2) return null;
  const op = b[0] & 0x0f, masked = b[1] & 0x80;
  let len = b[1] & 0x7f, off = 2;
  if (len === 126) { if (b.length < 4) return null; len = b.readUInt16BE(2); off = 4; }
  else if (len === 127) { if (b.length < 10) return null; len = Number(b.readBigUInt64BE(2)); off = 10; }
  const maskLen = masked ? 4 : 0;
  if (b.length < off + maskLen + len) return null;
  let data = b.subarray(off + maskLen, off + maskLen + len);
  if (masked) {
    const m = b.subarray(off, off + 4);
    data = Buffer.from(data);
    for (let i = 0; i < data.length; i++) data[i] ^= m[i & 3];
  }
  c.buf = b.subarray(off + maskLen + len);
  return { op, data };
}

function writeFrame(socket, op, payload) {
  const len = payload.length;
  let head;
  if (len < 126) head = Buffer.from([0x80 | op, len]);
  else if (len < 65536) { head = Buffer.alloc(4); head[0] = 0x80 | op; head[1] = 126; head.writeUInt16BE(len, 2); }
  else { head = Buffer.alloc(10); head[0] = 0x80 | op; head[1] = 127; head.writeBigUInt64BE(BigInt(len), 2); }
  try { socket.write(Buffer.concat([head, payload])); } catch {}
}

function send(c, obj) { writeFrame(c.socket, 1, Buffer.from(JSON.stringify(obj))); }
function broadcast(obj) { const p = Buffer.from(JSON.stringify(obj)); for (const c of clients) writeFrame(c.socket, 1, p); }
function broadcastState() { broadcast({ t: "state", s: state }); }
function broadcastCount() { broadcast({ t: "count", n: clients.size }); }

// ---------- 메시지 처리 ----------
const spinning = () => state.spin && Date.now() < state.spin.startAt + state.spin.durMs;

function cleanNames(arr) {
  return Array.isArray(arr)
    ? arr.filter((x) => typeof x === "string").map((x) => x.trim().slice(0, 40)).filter(Boolean).slice(0, MAX_NAMES)
    : [];
}

function handle(c, m) {
  if (m.t === "ping") return send(c, { t: "pong", c: m.c, s: Date.now() });
  if (m.t === "auth") {
    c.isHost = typeof m.key === "string" && m.key.length === HOST_KEY.length &&
      crypto.timingSafeEqual(Buffer.from(m.key), Buffer.from(HOST_KEY));
    return send(c, { t: "role", host: c.isHost });
  }
  if (!c.isHost) return; // 아래는 진행자만 가능

  if (m.t === "names" && !spinning()) {
    state.names = cleanNames(m.names);
    broadcastState();
  } else if (m.t === "spin" && !spinning()) {
    const names = state.names.slice();
    if (names.length < 2) return;
    const durMs = Math.min(20000, Math.max(3000, (Number(m.durSec) || 8) * 1000));
    const winnerIdx = crypto.randomInt(names.length);
    const seg = TAU / names.length;
    const from = state.rest;
    // 화면 위쪽(-90도) 포인터에 당첨 칸의 가운데 근처가 오도록 최종 각도 계산
    const jitter = (Math.random() - 0.5) * seg * 0.7;
    const target = -Math.PI / 2 - (winnerIdx + 0.5) * seg + jitter;
    const delta = (((target - from) % TAU) + TAU) % TAU;
    const turns = Math.round(durMs / 1000) + 3;
    const to = from + turns * TAU + delta;
    const id = crypto.randomBytes(6).toString("hex");
    const startAt = Date.now() + COUNTDOWN_MS;
    state.spin = { id, names, from, to, startAt, durMs, winnerIdx, winner: names[winnerIdx] };
    state.showWinner = false;
    broadcastState();
    clearTimeout(spinTimer);
    spinTimer = setTimeout(() => {
      state.rest = to % TAU;
      state.history.unshift({ name: names[winnerIdx], at: Date.now(), id });
      state.history = state.history.slice(0, 200);
      state.showWinner = true;
      broadcastState();
    }, startAt + durMs - Date.now());
  } else if (m.t === "close" && !spinning()) {
    state.showWinner = false;
    if (m.remove && state.spin) {
      const i = state.names.indexOf(state.spin.winner);
      if (i >= 0) state.names.splice(i, 1);
    }
    broadcastState();
  } else if (m.t === "clearHistory") {
    state.history = [];
    broadcastState();
  }
}

server.listen(PORT, () => console.log("추첨기 서버 실행 중: http://localhost:" + PORT));
