// Tests for the agent-group source behind the team switcher.
//
// groups.js talks to the Wazuh manager API over HTTPS, so — like the auth
// tests — this runs against a REAL local HTTPS server that mimics the manager
// (authenticate -> token, /groups, /agents). A mock of the transport would let
// a bug in the actual https/token/parse path pass; a real socket does not.
//
// The behaviours that matter, and the failure each guards against:
//   * resolution is correct                 (wrong team -> wrong hosts)
//   * an unknown/empty group -> []          (must yield zero results, not all)
//   * API down/creds unset -> null          ("down" must be distinguishable
//                                            from "empty", or a team filter
//                                            silently leaks every host)
//   * an expired token is retried once      (transient 401 shouldn't blank the UI)
import test from "node:test";
import assert from "node:assert/strict";
import https from "node:https";

// Throwaway self-signed localhost cert — groups.js sets rejectUnauthorized:false,
// so it need only be a valid pair, never trusted. Not a secret.
const KEY = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCu+vrh5yEVl84E
fjPeAlt2c82cXRWQrHyrYec0+t/z7ABODOe2kUYS4FEOu8vL5SQS+j2fDXF1KACO
rVuAQr/gBNdnh48TF5hggHo6eckJcUUKJ8flpagCQrDuQoo7j5FRLkQD5wMeaU0R
sikxAzxsJEHj1mAWoZWZKCWMpBhE3M+Pk+x1FMq47p3CCJX9H3Yplo28PuSaP4yV
yFMcv7BjNj6JiSBBLw1C86LhWnlfXoZEJrxLqjx1cEjtEcHyCRB52rwVazQrgLT8
3oUsRDFoqaFOpc2jKnkEeyxr51GNImH88sT5niQwHx1IXhqk+Xj+30DoK89+rIur
68iCaKnFAgMBAAECggEAAxw6dpFUwk0VECQ3I03a7CzW8t3TtY3fVxjcfXxXxpPu
FcppxFIU6F5837HBB7Izv95GAfcA9TJoFMvU5HTV83Mv6gBGmodblxw0L/28r/0y
Wzca+O8cIKgopso01KYIEPpCeBL0jac/rl4X7divIQP2+N1gDrRCFBDFiW2xnGhh
25SWm27I4F51tMZ1bD5JttI6y4451hTKttmY9yFGShBNEDn/FyEoSuvHg8Eobqeo
vW0g1j1sQ8eG9ZxG7ANZTydY4Bkt9GcP+rrUt58+zbRvSNP+CLE9bFCRnOZIkyqh
eDHFE98OckIFkniRM5rWL4GRrB9VlgvwP1GsHms62QKBgQDURy9zSPe6spLi1xS7
TB3PkBL7EfZ6skdk9hXQ97pDvL39Z/sLiYQsbiHJgZPJiaaYJ+r7tR1ldMldee1k
+EwC2U360XzPibR1beezP6i3jstrVaF1zicyj3Rz9JeJ6uwy93j+jS9rvyawFFcY
Q15/cenxYZxHGDVYNYeKde2+fQKBgQDTBTHn8bMuWrVNPlCHx6ZxMVe0oN2BvMI7
E++RiFqnRQrEwps3EEkVqntszl4+Cozcv7nRPtPuO/De7hAoGLhGorHZ3zcHo1Bn
YV6OuaZjgGkjEhmikHFnVen3almxYDPPSCgFK45ZzYzyfPmMPeLhvcxqKnZTHeKU
couOXl+S6QKBgCSpsslPhfHJ29Kv4RXEPLXXpV+Vp6NjXS9TzUrNLm96jrnQlqxU
cO6XiuBZr+O0EYDgDBazHkOimxC4+UZiGAa571zth4f0uaU6eTUdPo+Naxa7sGo/
U8fIvQ015mJcn7ThxxT334PVfOIWcUBwikaqrwQQnsQsqzHz9Nf2LDylAoGAYLY8
zSTFDjWcai5pEhG6gp4uqCYh3tf33MOiRHzNr2PBL7RRFsdr93YO4yshniWPsYxd
ST0WPFVUa5eH6BiMPDNMd6IJwoJi0z6Y66jCTVAI333oKc0xbD6/4BjpypVgqVtU
nCn+L8I5GtmUNWYXmYY3LWEQob9MnORyeWlfPCECgYEAppN6/P7HtbBUos55CooS
6XmTj8+IdXSGH1zcEigBb+zz+IN2n6jrh/uRV00f1D4wrXxPCk3I+5guNFwdyhl0
DMhPWxnLb8g8OTC6n//JdwUb5Rb0CziSHyz7RGF6ETeBpDYgvHrbXZjmQJvCf13x
5lafepAT4TGHzRdzK4U9c6M=
-----END PRIVATE KEY-----`;
const CERT = `-----BEGIN CERTIFICATE-----
MIIDCTCCAfGgAwIBAgIUVXyPadKJSw4A6pAHPfLJa0qMUHcwDQYJKoZIhvcNAQEL
BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI2MDgwMTA4NTkxN1oXDTM2MDcy
OTA4NTkxN1owFDESMBAGA1UEAwwJbG9jYWxob3N0MIIBIjANBgkqhkiG9w0BAQEF
AAOCAQ8AMIIBCgKCAQEArvr64echFZfOBH4z3gJbdnPNnF0VkKx8q2HnNPrf8+wA
TgzntpFGEuBRDrvLy+UkEvo9nw1xdSgAjq1bgEK/4ATXZ4ePExeYYIB6OnnJCXFF
CifH5aWoAkKw7kKKO4+RUS5EA+cDHmlNEbIpMQM8bCRB49ZgFqGVmSgljKQYRNzP
j5PsdRTKuO6dwgiV/R92KZaNvD7kmj+MlchTHL+wYzY+iYkgQS8NQvOi4Vp5X16G
RCa8S6o8dXBI7RHB8gkQedq8FWs0K4C0/N6FLEQxaKmhTqXNoyp5BHssa+dRjSJh
/PLE+Z4kMB8dSF4apPl4/t9A6CvPfqyLq+vIgmipxQIDAQABo1MwUTAdBgNVHQ4E
FgQUNutp7ypHI3Cb9XSzBrNWEsxXJCwwHwYDVR0jBBgwFoAUNutp7ypHI3Cb9XSz
BrNWEsxXJCwwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAZyEI
gOlsW3Fr0rHYPuareniamRl/TRB163JIMxg0RCd9+QhgbPSLmZWG/dOPuspXMqXA
GUo6jlENPIv6T45PlXwhBElE7nzJw4+bm3XfOPNHNuLCt/BKteDOTlAXm8P5++Lm
O5MlgMqJtMTWWG6WIEMn6lyZ3qc1cCILF+JevD+D8ZPl0Lkv4ywwrjZ6u4xWO+Ep
c1Pmg9JUVZivGSHsJKd7ExmaTlEAumM3dKA+40JKcbfenQQsTRPJ+FKkZ9C86IaN
v/vE5GqpXDTmNBP3s4xr7WNWqBILAlNYJv7mgM4ZR8hYhENlD+2otSj3OcIzcs2c
CX2bJPMqPL/jktvUgQ==
-----END CERTIFICATE-----`;

/** A fake manager API. Behaviour is tunable per test via `opts`. */
function startManager(opts = {}) {
  const state = { authCalls: 0, tokenSeq: 0, ...opts };
  const server = https.createServer({ key: KEY, cert: CERT }, (req, res) => {
    const url = req.url || "";
    if (req.method === "POST" && url.startsWith("/security/user/authenticate")) {
      state.authCalls += 1;
      if (state.failAuth) { res.writeHead(401).end("unauthorized"); return; }
      state.tokenSeq += 1;
      res.writeHead(200, { "content-type": "text/plain" });
      res.end(`token-${state.tokenSeq}-${"x".repeat(30)}`); // raw=true => bare token
      return;
    }
    // Expire the first-issued token once, to exercise the 401 re-auth path.
    if (state.expireFirstToken && (req.headers.authorization || "").includes("token-1-")) {
      res.writeHead(401).end("expired"); return;
    }
    if (url.startsWith("/groups")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ data: { affected_items: state.groups } }));
      return;
    }
    if (url.startsWith("/agents")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ data: { affected_items: state.agents } }));
      return;
    }
    res.writeHead(404).end("nope");
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () =>
      resolve({ server, port: server.address().port, state }));
  });
}

/** Import a FRESH groups.js bound to a given API url + creds (module caches). */
async function freshGroups({ port, user = "wazuh-wui", password = "pw", ttl = "0" } = {}) {
  process.env.WAZUH_API_URL = port ? `https://127.0.0.1:${port}` : "https://127.0.0.1:1";
  if (user === null) delete process.env.WAZUH_API_USER; else process.env.WAZUH_API_USER = user;
  if (password === null) delete process.env.WAZUH_API_PASSWORD; else process.env.WAZUH_API_PASSWORD = password;
  process.env.WAZUH_GROUPS_TTL_MS = ttl; // 0 = never serve stale, so each call refetches
  return import(`../server/groups.js?t=${Math.random().toString(16).slice(2)}`);
}

const GROUPS = [
  { name: "sec-team", count: 2 },
  { name: "network-team", count: 1 },
  { name: "dev-team", count: 0 },
];
const AGENTS = [
  { name: "SEC-01", group: ["sec-team"] },
  { name: "SEC-02", group: ["sec-team", "default"] },
  { name: "NET-01", group: ["network-team"] },
];

// --- Resolution -------------------------------------------------------------

test("list() returns the groups with their counts", async () => {
  const m = await startManager({ groups: GROUPS, agents: AGENTS });
  try {
    const g = await freshGroups({ port: m.port });
    assert.deepEqual(await g.list(), GROUPS);
    assert.equal(g.enabled(), true);
  } finally { m.server.close(); }
});

test("agentsIn() maps a group to exactly its member host names", async () => {
  const m = await startManager({ groups: GROUPS, agents: AGENTS });
  try {
    const g = await freshGroups({ port: m.port });
    assert.deepEqual((await g.agentsIn("sec-team")).sort(), ["SEC-01", "SEC-02"]);
    assert.deepEqual(await g.agentsIn("network-team"), ["NET-01"]);
  } finally { m.server.close(); }
});

test("an agent in two groups is counted in both", async () => {
  const m = await startManager({ groups: GROUPS, agents: AGENTS });
  try {
    const g = await freshGroups({ port: m.port });
    assert.ok((await g.agentsIn("default")).includes("SEC-02"));
    assert.ok((await g.agentsIn("sec-team")).includes("SEC-02"));
  } finally { m.server.close(); }
});

// --- The empty-vs-unavailable distinction (the load-bearing one) ------------

test("a group with no members resolves to [] — zero results, not everything", async () => {
  const m = await startManager({ groups: GROUPS, agents: AGENTS });
  try {
    const g = await freshGroups({ port: m.port });
    const r = await g.agentsIn("dev-team");
    assert.deepEqual(r, [], "an empty team must scope to nothing, not fall through to all");
    assert.notEqual(r, null, "empty is a real answer, distinct from unavailable");
  } finally { m.server.close(); }
});

test("an unknown group resolves to [] (nothing), not null", async () => {
  const m = await startManager({ groups: GROUPS, agents: AGENTS });
  try {
    const g = await freshGroups({ port: m.port });
    assert.deepEqual(await g.agentsIn("no-such-team"), []);
  } finally { m.server.close(); }
});

test("when the API is unreachable, resolution is null — never a silent []", async () => {
  // Point at a dead port. A team filter must then fail loud (caller answers
  // 503), not resolve to "no hosts" and look like a quiet, empty team.
  const g = await freshGroups({ port: null });
  assert.equal(await g.agentsIn("sec-team"), null);
  assert.deepEqual(await g.list(), []);
});

test("with creds unset the feature is disabled: enabled() false, list empty, resolve null", async () => {
  const g = await freshGroups({ user: null, password: null });
  assert.equal(g.enabled(), false);
  assert.deepEqual(await g.list(), []);
  assert.equal(await g.agentsIn("sec-team"), null);
});

test("failed authentication is treated as unavailable, not empty", async () => {
  const m = await startManager({ groups: GROUPS, agents: AGENTS, failAuth: true });
  try {
    const g = await freshGroups({ port: m.port });
    assert.equal(await g.agentsIn("sec-team"), null);
  } finally { m.server.close(); }
});

// --- Token handling ---------------------------------------------------------

test("an expired token triggers exactly one re-auth, transparently", async () => {
  const m = await startManager({ groups: GROUPS, agents: AGENTS, expireFirstToken: true });
  try {
    const g = await freshGroups({ port: m.port });
    // First data fetch: token-1 is rejected once, re-auth to token-2 succeeds.
    assert.deepEqual((await g.agentsIn("sec-team")).sort(), ["SEC-01", "SEC-02"]);
    assert.ok(m.state.authCalls >= 2, "should have re-authenticated after the 401");
  } finally { m.server.close(); }
});
