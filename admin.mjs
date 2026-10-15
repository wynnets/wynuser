// Admin API: POST /api/admin   header: x-admin-key: <ADMIN_PASSWORD>
// Every action is written to the audit log (Log tab in the admin panel).
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

const getPassword = () => globalThis.Netlify?.env?.get?.("ADMIN_PASSWORD") || process.env.ADMIN_PASSWORD || "";
function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
const norm = (v) => String(v || "").trim().replace(/^@/, "").toLowerCase().slice(0, 20);
const SOCIAL = ["Minecraft", "Roblox", "Telegram", "Discord", "TikTok", "Instagram", "X - Twitter"];
const CATS = { usernames: SOCIAL, numbers: [], proxy: SOCIAL, gifts: [], gaming: ["Minecraft", "Roblox", "CS GO", "Fortnite"], other: [] };
/** minutes -> absolute time, 0 / empty = forever */
const untilFrom = (minutes) => (Number(minutes) > 0 ? Date.now() + Number(minutes) * 60000 : 0);

export default async (req) => {
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  const password = getPassword();
  if (!password) return json({ error: "ADMIN_PASSWORD is not set in Netlify environment variables." }, 500);
  if (!safeEqual(req.headers.get("x-admin-key") || "", password)) {
    await new Promise((r) => setTimeout(r, 600));
    return json({ error: "Wrong password." }, 401);
  }
  let body;
  try { body = await req.json(); } catch { return json({ error: "Invalid request." }, 400); }
  const st = stores();

  const rejectWhere = async (pred, note) => {
    const hit = (await allListings(st)).filter(pred);
    await Promise.all(hit.map((x) => st.listings.setJSON(`l/${x.id}`, { ...x, status: "rejected", pinned: false, modNote: note })));
    return hit.length;
  };
  const needUser = async (name) => {
    const u = await getUser(st, norm(name));
    if (!u) throw Object.assign(new Error("No account with that username."), { status: 404 });
    return u;
  };
  const saveUser = (u) => st.users.setJSON(`u/${u.key}`, u);

  try {
    switch (body.action) {
      /* ================= overview ================= */
      case "stats": {
        const listings = await allListings(st);
        const { blobs: ub } = await st.users.list({ prefix: "u/" });
        const { blobs: bb } = await st.bans.list();
        const day = Date.now() - 864e5;
        const support = Object.values((await readInbox(st, SUPPORT)).convos).reduce((n, c) => n + (c.unread || 0), 0);
        return json({
          users: ub.length,
          live: listings.filter((l) => l.status === "approved").length,
          pending: listings.filter((l) => l.status === "pending").length,
          rejected: listings.filter((l) => l.status === "rejected").length,
          pinned: listings.filter((l) => l.pinned).length,
          today: listings.filter((l) => l.createdAt > day).length,
          bans: bb.length,
          supportUnread: support,
        });
      }
      case "log":
        return json({ items: (await st.meta.get("audit", { type: "json" })) || [] });

      /* ================= threads ================= */
      case "list":
        return json({ items: (await allListings(st)).sort((a, b) => b.createdAt - a.createdAt) });
      case "proof":
        return json({ proof: (await st.proofs.get(String(body.id))) || null });
      case "status": {
        if (!["pending", "approved", "rejected"].includes(body.status)) return json({ error: "Bad status." }, 400);
        const l = await st.listings.get(`l/${body.id}`, { type: "json" });
        if (!l) return json({ error: "Thread not found." }, 404);
        l.status = body.status;
        if (body.status === "approved") l.approvedAt = l.approvedAt || Date.now();
        if (body.status !== "approved") l.pinned = false;
        if (body.note !== undefined) l.modNote = String(body.note).slice(0, 300);
        await st.listings.setJSON(`l/${l.id}`, l);
        await audit(st, `thread ${body.status}`, l.title, l.authorName || l.author);
        return json({ ok: true });
      }
      case "pin": {
        const l = await st.listings.get(`l/${body.id}`, { type: "json" });
        if (!l) return json({ error: "Thread not found." }, 404);
        l.pinned = !!body.pinned;
        l.pinnedAt = l.pinned ? Date.now() : 0;
        if (l.pinned && l.status !== "approved") { l.status = "approved"; l.approvedAt = l.approvedAt || Date.now(); }
        await st.listings.setJSON(`l/${l.id}`, l);
        await audit(st, l.pinned ? "pinned thread" : "unpinned thread", l.title);
        return json({ ok: true });
      }
      case "editListing": {
        const l = await st.listings.get(`l/${body.id}`, { type: "json" });
        if (!l) return json({ error: "Thread not found." }, 404);
        const f = body.fields || {};
        if (f.category !== undefined) {
          if (!(f.category in CATS)) return json({ error: "Unknown category." }, 400);
          l.category = f.category;
          l.sub = CATS[f.category].length ? (CATS[f.category].includes(f.sub) ? f.sub : CATS[f.category][0]) : "";
        }
        if (f.title !== undefined) { const t = clean(f.title, 64).replace(/^@/, ""); if (!t) return json({ error: "Title can't be empty." }, 400); l.title = t; }
        if (f.price !== undefined) { const p = Math.round(Number(f.price) * 100) / 100; if (!(p > 0)) return json({ error: "Enter a valid price." }, 400); l.price = p; }
        if (f.description !== undefined) l.description = clean(f.description, 1500);
        if (f.modNote !== undefined) l.modNote = clean(f.modNote, 300);
        l.editedAt = Date.now();
        await st.listings.setJSON(`l/${l.id}`, l);
        await audit(st, "edited thread", l.title);
        return json({ ok: true, item: l });
      }
      case "createListing": {
        // Official thread posted by wynuser itself: no proof, live immediately
        const f = body.fields || {};
        if (!(f.category in CATS)) return json({ error: "Choose a category." }, 400);
        const title = clean(f.title, 64).replace(/^@/, "");
        const price = Math.round(Number(f.price) * 100) / 100;
        if (!title) return json({ error: "Fill in the title." }, 400);
        if (!(price > 0)) return json({ error: "Enter a valid price." }, 400);
        const id = Date.now().toString(36) + randomBytes(3).toString("hex");
        const l = {
          id, category: f.category, sub: CATS[f.category].length ? (CATS[f.category].includes(f.sub) ? f.sub : CATS[f.category][0]) : "",
          title, price, description: clean(f.description, 1500), author: SUPPORT, authorName: "wynuser",
          status: "approved", createdAt: Date.now(), approvedAt: Date.now(), pinned: !!f.pinned, pinnedAt: f.pinned ? Date.now() : 0, official: true,
        };
        await st.listings.setJSON(`l/${id}`, l);
        await audit(st, "posted official thread", title);
        return json({ ok: true, item: l });
      }
      case "delete": {
        const l = await st.listings.get(`l/${body.id}`, { type: "json" });
        await st.listings.delete(`l/${body.id}`);
        await st.proofs.delete(String(body.id));
        await audit(st, "deleted thread", l?.title || body.id);
        return json({ ok: true });
      }

      /* ================= bans ================= */
      case "ban": {
        // From a thread: ban its author by account / IP / device
        const l = await st.listings.get(`l/${body.id}`, { type: "json" });
        if (!l) return json({ error: "Thread not found." }, 404);
        const reason = String(body.reason || "").slice(0, 300);
        const until = untilFrom(body.minutes);
        const scope = body.scope || { user: true, ip: true, cid: true };
        const rec = { reason, at: Date.now(), until, fromThread: l.id, username: l.authorName || l.author };
        const keys = [];
        if (scope.user && l.author && l.author !== SUPPORT) keys.push(`user:${l.author}`);
        if (scope.ip && l.ip && l.ip !== "unknown") keys.push(`ip:${l.ip}`);
        if (scope.cid && l.clientId) keys.push(`cid:${l.clientId}`);
        await Promise.all(keys.map((k) => st.bans.setJSON(k, { ...rec, key: k })));
        const rejected = await rejectWhere(
          (x) => (scope.user && x.author && x.author === l.author) ||
                 (scope.ip && x.ip === l.ip && l.ip !== "unknown") ||
                 (scope.cid && x.clientId && x.clientId === l.clientId),
          `Banned: ${reason}`
        );
        await audit(st, until ? "temp ban" : "ban", l.authorName || l.author, reason);
        return json({ ok: true, banned: keys, rejected });
      }
      case "banUser": {
        const u = await needUser(body.username);
        const reason = String(body.reason || "").slice(0, 300);
        const until = untilFrom(body.minutes);
        const rec = { reason, at: Date.now(), until, username: u.username };
        await st.bans.setJSON(`user:${u.key}`, { ...rec, key: `user:${u.key}` });
        const ip = u.lastIp || u.ip;
        if (body.withIp && ip && ip !== "unknown") await st.bans.setJSON(`ip:${ip}`, { ...rec, key: `ip:${ip}` });
        if (body.withDevice && u.clientId) await st.bans.setJSON(`cid:${u.clientId}`, { ...rec, key: `cid:${u.clientId}` });
        u.sessVer = (u.sessVer || 0) + 1; // kick them out
        await saveUser(u);
        const rejected = body.keepThreads ? 0 : await rejectWhere((x) => x.author === u.key, `Banned: ${reason}`);
        await audit(st, until ? "temp ban" : "ban", u.username, reason);
        return json({ ok: true, rejected });
      }
      case "bans": {
        const { blobs } = await st.bans.list();
        const items = (await Promise.all(blobs.map((b) => st.bans.get(b.key, { type: "json" })))).filter(Boolean)
          .filter((b) => !b.until || b.until > Date.now()).sort((a, b) => b.at - a.at);
        return json({ items });
      }
      case "unban":
        await st.bans.delete(String(body.key));
        await audit(st, "unban", body.key);
        return json({ ok: true });

      /* ================= mutes & warnings ================= */
      case "mute": {
        const u = await needUser(body.username);
        const scope = ["messages", "posting", "both"].includes(body.scope) ? body.scope : "both";
        u.mute = { scope, until: untilFrom(body.minutes), reason: clean(body.reason, 200), at: Date.now() };
        await saveUser(u);
        await audit(st, "mute", u.username, `${scope}${u.mute.until ? " until " + new Date(u.mute.until).toISOString() : " forever"} ${u.mute.reason}`);
        return json({ ok: true });
      }
      case "unmute": {
        const u = await needUser(body.username);
        delete u.mute;
        await saveUser(u);
        await audit(st, "unmute", u.username);
        return json({ ok: true });
      }
      case "warn": {
        const u = await needUser(body.username);
        const text = clean(body.reason, 500) || "Please follow the rules.";
        u.warnings = [...(u.warnings || []), { at: Date.now(), reason: text }].slice(-50);
        await saveUser(u);
        await sendMessage(st, SUPPORT, u.key, `Warning from moderators: ${text}`);
        await audit(st, "warn", u.username, text);
        return json({ ok: true, warnings: u.warnings.length });
      }

      /* ================= members ================= */
      case "users": {
        const { blobs } = await st.users.list({ prefix: "u/" });
        const users = (await Promise.all(blobs.map((b) => st.users.get(b.key, { type: "json" })))).filter(Boolean);
        const listings = await allListings(st);
        const { blobs: banBlobs } = await st.bans.list({ prefix: "user:" });
        const banned = new Set(banBlobs.map((b) => b.key.slice(5)));
        const items = users.map((u) => ({
          username: u.username, key: u.key, bio: u.bio || "", avatarVer: u.avatarVer || 0, badge: u.badge || "",
          createdAt: u.createdAt, ip: u.lastIp || u.ip, lastSeen: u.lastSeen || u.lastLoginAt || null, banned: banned.has(u.key),
          muted: !!(u.mute && (!u.mute.until || u.mute.until > Date.now())), warnings: (u.warnings || []).length,
          threads: listings.filter((l) => l.author === u.key).length,
          live: listings.filter((l) => l.author === u.key && l.status === "approved").length,
        })).sort((a, b) => b.createdAt - a.createdAt);
        return json({ items });
      }
      case "user": {
        const u = await needUser(body.username);
        const ban = await st.bans.get(`user:${u.key}`, { type: "json" });
        const listings = (await allListings(st)).filter((l) => l.author === u.key).sort((a, b) => b.createdAt - a.createdAt);
        const mute = u.mute && (!u.mute.until || u.mute.until > Date.now()) ? u.mute : null;
        return json({
          user: {
            username: u.username, key: u.key, uid: u.uid, bio: u.bio || "", badge: u.badge || "", avatarVer: u.avatarVer || 0,
            createdAt: u.createdAt, lastSeen: u.lastSeen || null, lastLoginAt: u.lastLoginAt || null,
            ip: u.ip, lastIp: u.lastIp || u.ip, clientId: u.clientId || "", warnings: u.warnings || [], mute,
            ban: ban && (!ban.until || ban.until > Date.now()) ? ban : null,
          },
          threads: listings.map((l) => ({ id: l.id, title: l.title, category: l.category, sub: l.sub, price: l.price, status: l.status, pinned: !!l.pinned, createdAt: l.createdAt })),
        });
      }
      case "editUser": {
        const u = await needUser(body.username);
        if (body.badge !== undefined) u.badge = clean(body.badge, 20);
        if (body.bio !== undefined) u.bio = clean(body.bio, 200);
        if (body.removeAvatar) { await st.avatars.delete(u.key); u.avatarVer = 0; }
        if (body.clearWarnings) u.warnings = [];
        await saveUser(u);
        await audit(st, "edited member", u.username, [body.badge !== undefined && `badge "${u.badge}"`, body.removeAvatar && "avatar removed", body.bio !== undefined && "bio changed", body.clearWarnings && "warnings cleared"].filter(Boolean).join(", "));
        return json({ ok: true });
      }
      case "resetPassword": {
        const u = await needUser(body.username);
        const temp = randomBytes(6).toString("base64url");
        Object.assign(u, hashPassword(temp));
        u.sessVer = (u.sessVer || 0) + 1;
        await saveUser(u);
        await audit(st, "reset password", u.username);
        return json({ ok: true, password: temp });
      }
      case "logoutAll": {
        const u = await needUser(body.username);
        u.sessVer = (u.sessVer || 0) + 1;
        await saveUser(u);
        await audit(st, "logged out everywhere", u.username);
        return json({ ok: true });
      }
      case "deleteUser": {
        const u = await needUser(body.username);
        if (body.withThreads) {
          const mine = (await allListings(st)).filter((l) => l.author === u.key);
          await Promise.all(mine.flatMap((l) => [st.listings.delete(`l/${l.id}`), st.proofs.delete(l.id)]));
        }
        await st.avatars.delete(u.key);
        await st.users.delete(`u/${u.key}`);
        await audit(st, "deleted account", u.username, body.withThreads ? "with threads" : "");
        return json({ ok: true });
      }

      /* ================= conversations ================= */
      case "userConvos": {
        const key = norm(body.username);
        const list = Object.values((await readInbox(st, key)).convos).sort((a, b) => b.updatedAt - a.updatedAt);
        const cards = await userCards(st, list.map((c) => c.with));
        return json({ items: list.map((c) => ({ with: c.with, user: cards[c.with], last: c.last, updatedAt: c.updatedAt })) });
      }
      case "convo": {
        const a = norm(body.a), b = norm(body.b);
        const convo = (await st.dm.get(convoKey(a, b), { type: "json" })) || { messages: [] };
        return json({ messages: convo.messages, users: await userCards(st, [a, b]) });
      }
      case "deleteMessage": {
        const a = norm(body.a), b = norm(body.b);
        const ck = convoKey(a, b);
        const convo = await st.dm.get(ck, { type: "json" });
        if (!convo) return json({ error: "Conversation not found." }, 404);
        const before = convo.messages.length;
        convo.messages = convo.messages.filter((m) => m.id !== body.id);
        await st.dm.setJSON(ck, convo);
        await audit(st, "deleted message", `${a} ↔ ${b}`);
        return json({ ok: true, removed: before - convo.messages.length });
      }

      /* ================= support inbox ================= */
      case "supportInbox": {
        const list = Object.values((await readInbox(st, SUPPORT)).convos).sort((a, b) => b.updatedAt - a.updatedAt);
        const cards = await userCards(st, list.map((c) => c.with));
        return json({ items: list.map((c) => ({ ...c, user: cards[c.with] })) });
      }
      case "supportOpen": {
        const other = norm(body.with);
        const convo = (await st.dm.get(convoKey(SUPPORT, other), { type: "json" })) || { messages: [] };
        await markRead(st, SUPPORT, other);
        return json({ messages: convo.messages, user: (await userCards(st, [other]))[other] });
      }
      case "supportSend": {
        const other = norm(body.to);
        const text = clean(body.text, 2000);
        if (!text) return json({ error: "Write a message first." }, 400);
        await needUser(other);
        return json({ ok: true, message: await sendMessage(st, SUPPORT, other, text) });
      }
      case "broadcast": {
        const text = clean(body.text, 2000);
        if (!text) return json({ error: "Write a message first." }, 400);
        const { blobs } = await st.users.list({ prefix: "u/" });
        const keys = blobs.map((b) => b.key.slice(2));
        for (const k of keys) await sendMessage(st, SUPPORT, k, text);
        await audit(st, "broadcast", `${keys.length} members`, text.slice(0, 120));
        return json({ ok: true, sent: keys.length });
      }

      /* ================= settings ================= */
      case "getSettings":
        return json({ settings: await getSettings(st) });
      case "setSettings": {
        const cur = await getSettings(st);
        const next = { ...cur };
        for (const k of Object.keys(DEFAULT_SETTINGS)) {
          if (body.settings?.[k] === undefined) continue;
          next[k] = typeof DEFAULT_SETTINGS[k] === "boolean" ? !!body.settings[k] : clean(body.settings[k], 300);
        }
        await st.meta.setJSON("settings", next);
        await audit(st, "changed settings", "", Object.keys(body.settings || {}).join(", "));
        return json({ ok: true, settings: next });
      }

      default:
        return json({ error: "Unknown action." }, 400);
    }
  } catch (e) {
    return json({ error: e.message || "Something went wrong." }, e.status || 500);
  }
};

export const config = { path: "/api/admin" };
