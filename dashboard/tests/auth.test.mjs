// Regression tests for authentication and RBAC.
//
// These run against a real Express app on a real socket rather than calling the
// middleware directly, because the thing worth protecting is the whole path:
// cookie -> session lookup -> role comparison -> req.session. A unit test of
// requireRole() in isolation would still pass if the guard were never mounted.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import express from "express";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "dl-auth-"));
process.env.DASH_USERS_FILE = path.join(tmp, "users.json");
delete process.env.DASH_AUTH_DISABLED;
delete process.env.DASH_PASSWORD_HASH;

const { installAuth, requireRole, hashPassword, verifyPassword, ROLES } =
  await import("../server/auth.js");

const PASSWORDS = { vic: "viewer-pw", ana: "analyst-pw", adi: "admin-pw" };
fs.writeFileSync(process.env.DASH_USERS_FILE, JSON.stringify([
  { username: "vic", hash: hashPassword(PASSWORDS.vic), role: "viewer" },
  { username: "ana", hash: hashPassword(PASSWORDS.ana), role: "analyst" },
  { username: "adi", hash: hashPassword(PASSWORDS.adi), role: "admin" },
]));

// A stand-in for index.js: the auth guard, then routes at each privilege level.
const app = express();
app.use(express.json());
installAuth(app, {});
app.get("/api/open", (req, res) => res.json({ user: req.session.user }));
app.get("/api/analyst", requireRole("analyst"), (req, res) => res.json({ user: req.session.user }));
app.get("/api/admin", requireRole("admin"), (req, res) => res.json({ user: req.session.user }));

const server = app.listen(0);
await new Promise((r) => server.once("listening", r));
const BASE = `http://127.0.0.1:${server.address().port}`;

/** Log in and return the session cookie, or null when the login failed. */
async function signIn(username, password) {
  const res = await fetch(`${BASE}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) return null;
  return res.headers.getSetCookie().map((c) => c.split(";")[0]).join("; ");
}

const as = (cookie, url) => fetch(`${BASE}${url}`, { headers: cookie ? { cookie } : {} });

// --- Password hashing -------------------------------------------------------

test("a password verifies against its own hash and nothing else", () => {
  const stored = hashPassword("correct horse battery staple");
  assert.ok(verifyPassword("correct horse battery staple", stored));
  assert.ok(!verifyPassword("Correct horse battery staple", stored));
  assert.ok(!verifyPassword("", stored));
});

test("the same password hashes differently every time (salted)", () => {
  assert.notEqual(hashPassword("same"), hashPassword("same"));
});

test("a malformed stored hash fails closed instead of throwing", () => {
  for (const bad of ["", "not-a-hash", "md5:1:2:3:aa:bb", "scrypt:only:four:parts"]) {
    assert.equal(verifyPassword("anything", bad), false);
  }
});

// --- Login ------------------------------------------------------------------

test("valid credentials return the user's role and a session cookie", async () => {
  const res = await fetch(`${BASE}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "ana", password: PASSWORDS.ana }),
  });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { user: "ana", role: "analyst" });
  const cookie = res.headers.getSetCookie().join(";");
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);
});

test("a wrong password is rejected", async () => {
  assert.equal(await signIn("ana", "not-the-password"), null);
});

test("an unknown username is rejected the same way as a wrong password", async () => {
  const res = await fetch(`${BASE}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "nobody", password: "whatever" }),
  });
  assert.equal(res.status, 401);
  // The message must not reveal whether the account exists.
  assert.equal((await res.json()).error, "Invalid username or password");
});

test("a non-string password cannot bypass verification", async () => {
  for (const password of [null, 123, { toString: () => PASSWORDS.ana }, ["x"]]) {
    const res = await fetch(`${BASE}/api/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "ana", password }),
    });
    assert.equal(res.status, 401);
  }
});

// --- The session guard ------------------------------------------------------

test("every API route is closed without a session", async () => {
  for (const url of ["/api/open", "/api/analyst", "/api/admin", "/api/auth/session"]) {
    assert.equal((await as(null, url)).status, 401, `${url} must require a session`);
  }
});

test("a forged cookie does not grant access", async () => {
  assert.equal((await as("dl_session=" + "a".repeat(64), "/api/open")).status, 401);
});

test("logging out invalidates the cookie immediately", async () => {
  const cookie = await signIn("ana", PASSWORDS.ana);
  assert.equal((await as(cookie, "/api/open")).status, 200);
  await fetch(`${BASE}/api/auth/logout`, { method: "POST", headers: { cookie } });
  assert.equal((await as(cookie, "/api/open")).status, 401, "the old cookie must be dead");
});

// --- RBAC -------------------------------------------------------------------

test("roles are ordered least- to most-privileged", () => {
  assert.deepEqual(ROLES, ["viewer", "analyst", "admin"]);
});

test("a viewer can read but cannot triage or see the audit log", async () => {
  const cookie = await signIn("vic", PASSWORDS.vic);
  assert.equal((await as(cookie, "/api/open")).status, 200);
  assert.equal((await as(cookie, "/api/analyst")).status, 403);
  assert.equal((await as(cookie, "/api/admin")).status, 403);
});

test("an analyst can triage but cannot see the audit log", async () => {
  const cookie = await signIn("ana", PASSWORDS.ana);
  assert.equal((await as(cookie, "/api/analyst")).status, 200);
  assert.equal((await as(cookie, "/api/admin")).status, 403);
});

test("an admin passes every gate", async () => {
  const cookie = await signIn("adi", PASSWORDS.adi);
  for (const url of ["/api/open", "/api/analyst", "/api/admin"]) {
    assert.equal((await as(cookie, url)).status, 200);
  }
});

test("the acting username comes from the session, not the request", async () => {
  const cookie = await signIn("ana", PASSWORDS.ana);
  // A caller claiming to be someone else in the body/query is ignored: handlers
  // read req.session.user, which only the session can set.
  const res = await fetch(`${BASE}/api/analyst?user=adi`, {
    headers: { cookie, "x-user": "adi" },
  });
  assert.equal((await res.json()).user, "ana");
});

test.after(() => {
  server.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});
