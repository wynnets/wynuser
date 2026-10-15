// Direct messages: POST /api/messages  (needs a session)
//   { action: "inbox" }                      -> conversation list
//   { action: "open", with, after? }         -> messages with a member (marks them read)
//   { action: "send", to, text }             -> send a message
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

const MAX_PER_MINUTE = 20;

export default async (req, context) => {
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  const st = stores();
  const me = await currentUser(st, req);
  if (!me) return json({ error: "Log in to use messages." }, 401);
  let body;
  try { body = await req.json(); } catch { return json({ error: "Invalid request." }, 400); }

  const other = String(body.with || body.to || "").toLowerCase().replace(/^@/, "").slice(0, 20);

  switch (body.action) {
    case "inbox": {
      const inbox = await readInbox(st, me.key);
      const list = Object.values(inbox.convos).sort((a, b) => b.updatedAt - a.updatedAt);
      const cards = await userCards(st, list.map((c) => c.with));
      return json({ items: list.map((c) => ({ ...c, user: cards[c.with] })) });
    }

    case "open": {
      if (!other) return json({ error: "Choose a member." }, 400);
      const cards = await userCards(st, [other]);
      if (cards[other].gone) return json({ error: "No member with that username." }, 404);
      const convo = (await st.dm.get(convoKey(me.key, other), { type: "json" })) || { messages: [] };
      const after = Number(body.after) || 0;
      await markRead(st, me.key, other);
      return json({ user: cards[other], messages: convo.messages.filter((m) => m.at > after) });
    }

    case "send": {
      const text = clean(body.text, 2000);
      if (!other) return json({ error: "Choose a member." }, 400);
      if (other === me.key) return json({ error: "You can't message yourself." }, 400);
      if (!text) return json({ error: "Write a message first." }, 400);
      if (other !== SUPPORT && !(await getUser(st, other))) return json({ error: "No member with that username." }, 404);
      if (await findBan(st, { username: me.key })) return json({ error: "banned" }, 403);
      // Muted members and closed messaging still allow writing to support, so people can appeal
      if (other !== SUPPORT) {
        const m = activeMute(me, "messages");
        if (m) return json({ error: muteError(m) }, 403);
        if (!(await getSettings(st)).messaging) return json({ error: "Messages are paused right now. You can still write to support." }, 403);
      }

      const minute = Math.floor(Date.now() / 60000);
      const rl = `msg/${me.key}/${minute}`;
      const n = Number((await st.meta.get(rl)) || 0);
      if (n >= MAX_PER_MINUTE) return json({ error: "You're sending messages too fast. Wait a minute." }, 429);
      await st.meta.set(rl, String(n + 1));

      const msg = await sendMessage(st, me.key, other, text);
      return json({ ok: true, message: msg });
    }

    default:
      return json({ error: "Unknown action." }, 400);
  }
};

export const config = { path: "/api/messages" };
