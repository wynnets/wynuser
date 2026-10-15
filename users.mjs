// Members: GET /api/users?q=<text>  -> search by username
//          GET /api/users?u=<username> -> public profile + live threads
import { getStore } from "@netlify/blobs";
import { scryptSync, randomBytes, timingSafeEqual, createHash } from "node:crypto";

/* ---- shared helpers (same in every function file) ---- */
// Shared helpers for wynuser functions (not a function itself — lives outside netlify/functions)

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

const clean = (v, max) =>
  String(v ?? "").replace(/[\u0000-\u0008\u000b-\u001f\u007f]/g, "").trim().slice(0, max);

const S = (name) => getStore({ name, consistency: "strong" });
const stores = () => ({
  listings: S("listings"),
  proofs: S("proofs"),
  bans: S("bans"),
  users: S("users"),
  sessions: S("sessions"),
  meta: S("meta"),
  avatars: S("avatars"),
  dm: S("dm"),
  inbox: S("inbox"),
});

// Account names: start with a letter, 3–20 characters
const USERNAME_RE = /^[A-Za-z][A-Za-z0-9_]{2,19}$/;
const SESSION_DAYS = 365; // stay logged in for a year
const SUPPORT = "support"; // reserved pseudo-account answered from the admin panel

function hashPassword(password, salt = randomBytes(16).toString("hex")) {
  return { salt, hash: scryptSync(password, salt, 64).toString("hex") };
}
function verifyPassword(password, salt, hash) {
  const a = Buffer.from(scryptSync(password, salt, 64).toString("hex"));
  const b = Buffer.from(hash);
  return a.length === b.length && timingSafeEqual(a, b);
}

const sha = (s) => createHash("sha256").update(s).digest("hex");
const bearer = (req) => {
  const h = req.headers.get("authorization") || "";
  return h.startsWith("Bearer ") ? h.slice(7).trim() : "";
};

async function createSession(st, key, ver = 0) {
  const token = randomBytes(32).toString("hex");
  await st.sessions.setJSON(sha(token), { username: key, ver, exp: Date.now() + SESSION_DAYS * 864e5 });
  return token;
}
async function destroySession(st, req) {
  const token = bearer(req);
  if (token) await st.sessions.delete(sha(token));
}
/** User record for the request's session, or null. */
async function currentUser(st, req) {
  const token = bearer(req);
  if (!/^[a-f0-9]{64}$/.test(token)) return null;
  const s = await st.sessions.get(sha(token), { type: "json" });
  if (!s || s.exp < Date.now()) return null;
  const u = await st.users.get(`u/${s.username}`, { type: "json" });
  // "Log out everywhere" from the admin panel bumps sessVer, which kills older sessions
  if (!u || (s.ver || 0) !== (u.sessVer || 0)) return null;
  return u;
}
const getUser = (st, key) => st.users.get(`u/${String(key).toLowerCase()}`, { type: "json" });

const publicUser = (u) => ({
  username: u.username,
  key: u.key,
  bio: u.bio || "",
  avatarVer: u.avatarVer || 0,
  createdAt: u.createdAt,
  uid: u.uid || null,
  lastSeen: u.lastSeen || u.lastLoginAt || u.createdAt,
  badge: u.badge || "",
});

const clientIp = (req, context) =>
  context?.ip || req.headers.get("x-nf-client-connection-ip") || "unknown";

async function findBan(st, { username, ip, clientId }) {
  const keys = [
    username && `user:${username}`,
    ip && ip !== "unknown" && `ip:${ip}`,
    clientId && `cid:${clientId}`,
  ].filter(Boolean);
  for (const k of keys) {
    const b = await st.bans.get(k, { type: "json" });
    if (!b) continue;
    if (b.until && b.until < Date.now()) { await st.bans.delete(k); continue; } // temporary ban ran out
    return b;
  }
  return null;
}

/** Active mute for this user and scope ("messages" | "posting"), or null. */
function activeMute(user, scope) {
  const m = user?.mute;
  if (!m) return null;
  if (m.until && m.until < Date.now()) return null;
  if (m.scope !== "both" && m.scope !== scope) return null;
  return m;
}
const muteError = (m) =>
  `You're muted${m.until ? " until " + new Date(m.until).toUTCString().replace(" GMT", " UTC") : ""}${m.reason ? ": " + m.reason : "."}`;

/* ---------- site settings + audit log ---------- */
const DEFAULT_SETTINGS = {
  notice: "Every thread is reviewed by a moderator before it goes live. Keep deals in wynuser messages.",
  registrations: true,
  posting: true,
  messaging: true,
};
async function getSettings(st) {
  return { ...DEFAULT_SETTINGS, ...((await st.meta.get("settings", { type: "json" })) || {}) };
}
async function audit(st, action, target = "", detail = "") {
  const log = (await st.meta.get("audit", { type: "json" })) || [];
  log.unshift({ at: Date.now(), action, target: String(target).slice(0, 80), detail: String(detail).slice(0, 200) });
  await st.meta.setJSON("audit", log.slice(0, 400));
}

async function allListings(st) {
  const { blobs } = await st.listings.list({ prefix: "l/" });
  const all = await Promise.all(blobs.map((b) => st.listings.get(b.key, { type: "json" })));
  return all.filter(Boolean);
}

/* ---------- direct messages ---------- */
const convoKey = (a, b) => "c/" + [a, b].sort().join("__");
const MAX_KEEP = 500;

async function readInbox(st, key) {
  return (await st.inbox.get(`i/${key}`, { type: "json" })) || { convos: {} };
}

/** Append a message and update both inboxes. */
async function sendMessage(st, from, to, text) {
  const ck = convoKey(from, to);
  const convo = (await st.dm.get(ck, { type: "json" })) || { members: [from, to].sort(), messages: [] };
  const msg = { id: Date.now().toString(36) + randomBytes(3).toString("hex"), from, text, at: Date.now() };
  convo.messages.push(msg);
  if (convo.messages.length > MAX_KEEP) convo.messages = convo.messages.slice(-MAX_KEEP);
  convo.updatedAt = msg.at;
  await st.dm.setJSON(ck, convo);

  const preview = text.slice(0, 120);
  for (const [me, other] of [[from, to], [to, from]]) {
    const inbox = await readInbox(st, me);
    const prev = inbox.convos[other] || { unread: 0 };
    inbox.convos[other] = {
      with: other,
      last: preview,
      lastFrom: from,
      updatedAt: msg.at,
      unread: me === from ? 0 : (prev.unread || 0) + 1,
    };
    await st.inbox.setJSON(`i/${me}`, inbox);
  }
  return msg;
}

async function markRead(st, me, other) {
  const inbox = await readInbox(st, me);
  if (inbox.convos[other]?.unread) {
    inbox.convos[other].unread = 0;
    await st.inbox.setJSON(`i/${me}`, inbox);
  }
}

/** Attach display names + avatar versions for a list of user keys. */
async function userCards(st, keys) {
  const uniq = [...new Set(keys.filter(Boolean))];
  const out = {};
  await Promise.all(
    uniq.map(async (k) => {
      if (k === SUPPORT) { out[k] = { username: "wynuser support", key: SUPPORT, avatarVer: 0, staff: true }; return; }
      const u = await getUser(st, k);
      out[k] = u ? { username: u.username, key: u.key, avatarVer: u.avatarVer || 0, badge: u.badge || "" } : { username: k, key: k, avatarVer: 0, gone: true };
    })
  );
  return out;
}

/* ---- this function ---- */

export default async (req) => {
  if (req.method !== "GET") return json({ error: "Method not allowed" }, 405);
  const st = stores();
  const url = new URL(req.url);

  const u = (url.searchParams.get("u") || "").toLowerCase().replace(/^@/, "").slice(0, 20);
  if (u) {
    const user = await getUser(st, u);
    if (!user) return json({ error: "No member with that username." }, 404);
    const banned = !!(await st.bans.get(`user:${user.key}`));
    const threads = (await allListings(st))
      .filter((l) => l.author === user.key && l.status === "approved")
      .sort((a, b) => (b.approvedAt || 0) - (a.approvedAt || 0))
      .map((l) => ({ id: l.id, category: l.category, sub: l.sub, title: l.title, price: l.price, description: l.description, approvedAt: l.approvedAt, createdAt: l.createdAt }));
    return json({ user: { ...publicUser(user), banned }, threads });
  }

  const q = (url.searchParams.get("q") || "").toLowerCase().replace(/^@/, "").replace(/[^a-z0-9_]/g, "").slice(0, 20);
  if (!q) return json({ items: [] });
  const { blobs } = await st.users.list({ prefix: "u/" });
  const keys = blobs.map((b) => b.key.slice(2)).filter((k) => k.includes(q));
  keys.sort((a, b) => (a.startsWith(q) ? 0 : 1) - (b.startsWith(q) ? 0 : 1) || a.length - b.length || a.localeCompare(b));
  const users = (await Promise.all(keys.slice(0, 20).map((k) => getUser(st, k)))).filter(Boolean);
  return json({ items: users.map(publicUser) });
};

export const config = { path: "/api/users" };
