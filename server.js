const express = require("express"), crypto = require("crypto"), fs = require("fs"), path = require("path");
const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "20kb" }));

// --- tiny JSON-file store (swap for Postgres later) ---
const FILE = process.env.DATA_FILE || path.join(__dirname, "data.json");
let DB = { owners: {}, rooms: {} };
try { DB = JSON.parse(fs.readFileSync(FILE, "utf8")); } catch (e) {}
let dirty = false;
const save = () => { dirty = true; };
setInterval(() => { if (dirty) { dirty = false; fs.writeFile(FILE, JSON.stringify(DB), () => {}); } }, 2000);

const rnd = n => crypto.randomBytes(n).toString("hex");
const sha = s => crypto.createHash("sha256").update(String(s)).digest("hex");
const clip = (s, n) => String(s || "").trim().slice(0, n);
const hits = {};
function limit(key, max, ms) {
  const now = Date.now();
  hits[key] = (hits[key] || []).filter(t => now - t < ms);
  if (hits[key].length >= max) return false;
  hits[key].push(now);
  return true;
}
const fail = (res, code, msg) => res.status(code).json({ error: msg });
const view = r => ({ id: r.id, item: r.item, fname: r.fname, desc: r.desc, loc: r.loc, status: r.status, msgs: r.msgs });
const note = (o, text) => { o.notes.unshift({ id: rnd(4), text, t: Date.now(), read: false }); o.notes = o.notes.slice(0, 100); };
const LIMIT_PRE = 3, MAX_LEN = 500;

// --- auth helpers ---
const needOwner = (req, res, next) => {
  const h = sha(req.get("x-owner") || "none");
  const o = Object.values(DB.owners).find(x => x.tokenHash === h);
  if (!o) return fail(res, 401, "Please sign in again.");
  req.o = o; next();
};
const roomOf = req => {
  const h = sha(req.get("x-room") || "none");
  return Object.values(DB.rooms).find(r => r.tokenHash && r.tokenHash === h);
};

// --- owner ---
app.post("/api/register", (req, res) => {
  if (!limit("reg" + req.ip, 10, 3600e3)) return fail(res, 429, "Too many sign-ups. Try later.");
  const name = clip(req.body.name, 40);
  if (!name) return fail(res, 400, "Enter your name.");
  const token = rnd(24), id = rnd(6);
  DB.owners[id] = { id, name, email: clip(req.body.email, 120), tokenHash: sha(token), qrId: rnd(10), qrActive: true,
    pub: { name, note: "", ver: "blue-heron-42" }, notes: [], blocked: [] };
  save();
  res.json({ ownerToken: token });
});
app.get("/api/me", needOwner, (req, res) => {
  const o = req.o;
  res.json({ owner: { name: o.name, qrId: o.qrId, qrActive: o.qrActive, pub: o.pub },
    rooms: Object.values(DB.rooms).filter(r => r.ownerId === o.id).map(view), notes: o.notes, blocked: o.blocked.length });
});
app.post("/api/me/pub", needOwner, (req, res) => {
  req.o.pub = { name: clip(req.body.name, 40) || req.o.name, note: clip(req.body.note, 200), ver: clip(req.body.ver, 40) };
  save(); res.json({ ok: true });
});
app.post("/api/me/qr", needOwner, (req, res) => {
  if (req.body.op === "regen") req.o.qrId = rnd(10);
  else if (req.body.op === "toggle") req.o.qrActive = !req.o.qrActive;
  save(); res.json({ ok: true });
});
app.post("/api/me/notes/read", needOwner, (req, res) => { req.o.notes.forEach(n => n.read = true); save(); res.json({ ok: true }); });
app.post("/api/me/rooms/:id/msg", needOwner, (req, res) => {
  const r = DB.rooms[req.params.id];
  if (!r || r.ownerId !== req.o.id) return fail(res, 404, "Not found.");
  if (r.status !== "active") return fail(res, 409, "Accept the request first.");
  const t = clip(req.body.text, MAX_LEN); if (!t) return fail(res, 400, "Empty message.");
  r.msgs.push({ from: "owner", text: t, t: Date.now() }); save(); res.json({ ok: true });
});
const OPS = { accept: "active", reject: "rejected", close: "closed", recover: "recovered", block: "closed" };
const SYS = { accept: "Owner accepted the request.", reject: "Request rejected.", close: "Owner closed the chat.", recover: "Marked as recovered.", block: "Finder blocked." };
app.post("/api/me/rooms/:id/:op", needOwner, (req, res) => {
  const r = DB.rooms[req.params.id], op = req.params.op;
  if (!r || r.ownerId !== req.o.id || !OPS[op]) return fail(res, 404, "Not found.");
  if (op === "accept" && r.status !== "pending") return fail(res, 409, "Already handled.");
  if (op === "block") req.o.blocked.push(r.ipH);
  r.status = OPS[op];
  if (op !== "accept") r.tokenHash = null; // revoke finder access
  r.msgs.push({ from: "sys", text: SYS[op], t: Date.now() });
  save(); res.json({ ok: true });
});

// --- finder (anonymous) ---
const tagOwner = id => Object.values(DB.owners).find(o => o.qrId === String(id).toLowerCase());
app.get("/api/tag/:id", (req, res) => {
  const o = tagOwner(req.params.id);
  if (!o) return fail(res, 404, "Unknown tag.");
  if (!o.qrActive) return fail(res, 410, "Inactive tag.");
  res.json(o.pub);
});
app.post("/api/tag/:id/request", (req, res) => {
  const o = tagOwner(req.params.id);
  if (!o || !o.qrActive) return fail(res, 404, "Unknown tag.");
  const ipH = sha(req.ip);
  if (o.blocked.includes(ipH)) return fail(res, 403, "Unable to contact this owner.");
  if (!limit("req" + ipH, 5, 3600e3)) return fail(res, 429, "Request limit reached. Try again later.");
  const b = req.body, item = clip(b.item, 60), fname = clip(b.fname, 30), msg = clip(b.msg, MAX_LEN);
  if (!item || !fname || !msg) return fail(res, 400, "Item, display name and message are required.");
  const token = rnd(16), id = rnd(5);
  DB.rooms[id] = { id, ownerId: o.id, tokenHash: sha(token), ipH, item, fname, desc: clip(b.desc, 150), loc: clip(b.loc, 100),
    status: "pending", created: Date.now(), msgs: [{ from: "finder", text: msg, t: Date.now() }] };
  note(o, "Someone may have found your belongings: " + item + (b.loc ? " (" + clip(b.loc, 100) + ")" : ""));
  save(); res.json({ roomToken: token });
});
app.get("/api/room", (req, res) => { const r = roomOf(req); r ? res.json(view(r)) : fail(res, 404, "Conversation ended."); });
app.post("/api/room/msg", (req, res) => {
  const r = roomOf(req); if (!r) return fail(res, 404, "Conversation ended.");
  if (!limit("msg" + r.id, 20, 60e3)) return fail(res, 429, "Slow down a little.");
  if (r.status !== "pending" && r.status !== "active") return fail(res, 409, "This conversation is closed.");
  const used = r.msgs.filter(m => m.from === "finder").length;
  if (r.status === "pending" && used >= LIMIT_PRE) return fail(res, 409, "Wait for the owner to accept before sending more.");
  const t = clip(req.body.text, MAX_LEN); if (!t) return fail(res, 400, "Empty message.");
  r.msgs.push({ from: "finder", text: t, t: Date.now() });
  const o = DB.owners[r.ownerId]; if (o) note(o, "New message from " + r.fname + " about " + r.item);
  save(); res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, "public")));
app.listen(process.env.PORT || 3000, () => console.log("TagBack running"));
