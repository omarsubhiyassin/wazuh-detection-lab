// Session authentication for the dashboard BFF.
//
// Zero-dependency like the rest of the BFF: the password is scrypt-hashed
// (node:crypto), sessions live in an in-memory store keyed by a random 256-bit
// token carried in an httpOnly SameSite=Strict cookie. A BFF restart logs
// everyone out — acceptable for a single-tenant deployment.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const COOKIE_NAME = "dl_session";
const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 32 };

const USER = process.env.DASH_USER || "admin";
const PASSWORD_HASH = process.env.DASH_PASSWORD_HASH || "";
const AUTH_DISABLED = process.env.DASH_AUTH_DISABLED === "true";
const TTL_MS = Number(process.env.DASH_SESSION_TTL_HOURS || 12) * 3600_000;
const COOKIE_SECURE = process.env.DASH_COOKIE_SECURE === "true";

// Roles, least -> most privileged. viewer: read only. analyst: + triage.
// admin: + audit log / user management.
export const ROLES = ["viewer", "analyst", "admin"];
const USERS_FILE = process.env.DASH_USERS_FILE ||
  path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "users.json");

/**
 * The user directory. users.json ([{username, hash, role}]) when present, else
 * the single DASH_USER/DASH_PASSWORD_HASH as an admin (backward compatible).
 * Read on each login, so adding a user needs no BFF restart.
 */
export function loadUsers() {
  try {
    const arr = JSON.parse(fs.readFileSync(USERS_FILE, "utf8"));
    if (Array.isArray(arr) && arr.length) {
      return arr.filter((u) => u && u.username && u.hash).map((u) => ({
        username: String(u.username),
        hash: String(u.hash),
        role: ROLES.includes(u.role) ? u.role : "analyst",
      }));
    }
  } catch { /* no/invalid users.json — fall back to the single env user */ }
  return PASSWORD_HASH ? [{ username: USER, hash: PASSWORD_HASH, role: "admin" }] : [];
}

/** Hash a password into the stored `scrypt:N:r:p:salt:hash` format. */
export function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, SCRYPT.keylen, SCRYPT);
  return `scrypt:${SCRYPT.N}:${SCRYPT.r}:${SCRYPT.p}:${salt.toString("hex")}:${hash.toString("hex")}`;
}

/** Constant-time check of a password against a stored hash. */
export function verifyPassword(password, stored) {
  try {
    const [scheme, N, r, p, saltHex, hashHex] = String(stored).split(":");
    if (scheme !== "scrypt") return false;
    const expected = Buffer.from(hashHex, "hex");
    const actual = crypto.scryptSync(password, Buffer.from(saltHex, "hex"), expected.length,
      { N: Number(N), r: Number(r), p: Number(p) });
    return crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

// Verified against when the username doesn't match, so login timing doesn't
// reveal whether a username exists.
const DUMMY_HASH = hashPassword(crypto.randomBytes(8).toString("hex"));

const sessions = new Map(); // token -> { user, role, expiresAt }
setInterval(() => {
  const now = Date.now();
  for (const [t, s] of sessions) if (s.expiresAt <= now) sessions.delete(t);
}, 60_000).unref();

function parseCookies(header) {
  const out = {};
  for (const part of (header || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function sessionOf(req) {
  const token = parseCookies(req.headers.cookie)[COOKIE_NAME];
  if (!token) return null;
  const s = sessions.get(token);
  if (!s) return null;
  if (s.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  return { token, user: s.user, role: s.role };
}

/** Middleware: require a signed-in session with at least `minRole`. Attaches
 *  req.session = { user, role }. Use to gate write/admin endpoints. */
export function requireRole(minRole) {
  const min = ROLES.indexOf(minRole);
  return (req, res, next) => {
    const s = sessionOf(req);
    if (!s) return res.status(401).json({ error: "Not signed in" });
    if (ROLES.indexOf(s.role) < min) {
      return res.status(403).json({ error: `Requires ${minRole} role` });
    }
    req.session = s;
    next();
  };
}

// Failed-login throttle. Keyed by socket address: coarse (everything arrives
// from 127.0.0.1 behind the Vite dev proxy) but enough to stop online guessing.
const failures = new Map(); // ip -> { count, resetAt }
const MAX_FAILURES = 10;
const WINDOW_MS = 15 * 60_000;

function throttled(ip) {
  const f = failures.get(ip);
  return Boolean(f && f.resetAt > Date.now() && f.count >= MAX_FAILURES);
}

function recordFailure(ip) {
  const now = Date.now();
  const f = failures.get(ip);
  if (!f || f.resetAt <= now) failures.set(ip, { count: 1, resetAt: now + WINDOW_MS });
  else f.count += 1;
}

function setSessionCookie(res, token, maxAgeSec) {
  const attrs = [`${COOKIE_NAME}=${token}`, "Path=/", "HttpOnly", "SameSite=Strict", `Max-Age=${maxAgeSec}`];
  if (COOKIE_SECURE) attrs.push("Secure");
  res.setHeader("Set-Cookie", attrs.join("; "));
}

/**
 * Register /api/auth/* and a session guard covering everything else under
 * /api. Call after express.json() and before the API routes.
 */
export function installAuth(app, { onAuthEvent } = {}) {
  if (AUTH_DISABLED) {
    console.warn("[dashboard] DASH_AUTH_DISABLED=true — the API is UNAUTHENTICATED");
    app.get("/api/auth/session", (_req, res) => res.json({ user: "anonymous", role: "admin" }));
    app.post("/api/auth/logout", (_req, res) => res.json({ ok: true }));
    return;
  }
  if (!loadUsers().length) {
    console.error("[dashboard] no users configured (users.json or DASH_PASSWORD_HASH) — all logins will fail. Add one with: npm run add-user");
  }

  app.post("/api/auth/login", (req, res) => {
    const ip = req.socket.remoteAddress || "?";
    if (throttled(ip)) {
      return res.status(429).json({ error: "Too many failed attempts — try again in a few minutes" });
    }
    const users = loadUsers();
    if (!users.length) {
      return res.status(503).json({ error: "Login is not configured on the server" });
    }
    const { username, password } = req.body || {};
    const match = typeof username === "string" ? users.find((u) => u.username === username) : null;
    // Always run one verification (dummy hash on miss) so timing doesn't reveal
    // whether a username exists.
    const passOk = verifyPassword(typeof password === "string" ? password : "",
      match ? match.hash : DUMMY_HASH);
    if (!match || !passOk) {
      recordFailure(ip);
      return res.status(401).json({ error: "Invalid username or password" });
    }
    failures.delete(ip);
    const token = crypto.randomBytes(32).toString("hex");
    sessions.set(token, { user: match.username, role: match.role, expiresAt: Date.now() + TTL_MS });
    setSessionCookie(res, token, Math.floor(TTL_MS / 1000));
    onAuthEvent?.({ action: "login", user: match.username, role: match.role, ip });
    res.json({ user: match.username, role: match.role });
  });

  app.post("/api/auth/logout", (req, res) => {
    const s = sessionOf(req);
    if (s) { sessions.delete(s.token); onAuthEvent?.({ action: "logout", user: s.user, role: s.role }); }
    setSessionCookie(res, "", 0);
    res.json({ ok: true });
  });

  app.get("/api/auth/session", (req, res) => {
    const s = sessionOf(req);
    if (!s) return res.status(401).json({ error: "Not signed in" });
    res.json({ user: s.user, role: s.role });
  });

  // Guard everything else under /api and attach req.session for handlers.
  app.use("/api", (req, res, next) => {
    const s = sessionOf(req);
    if (!s) return res.status(401).json({ error: "Not signed in" });
    req.session = s;
    next();
  });
}
