#!/usr/bin/env node
// Manage the dashboard user directory (dashboard/users.json).
//
//   npm run add-user                 # interactive: username, role, password
//   npm run add-user -- --list       # list users (no hashes)
//   npm run add-user -- --delete bob # remove a user
//
// Passwords are scrypt-hashed (never stored plaintext); input is hidden.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { hashPassword, ROLES } from "../server/auth.js";

const FILE = process.env.DASH_USERS_FILE ||
  path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "users.json");

function read() {
  try { return JSON.parse(fs.readFileSync(FILE, "utf8")); } catch { return []; }
}
function write(users) {
  fs.writeFileSync(FILE, JSON.stringify(users, null, 2) + "\n", { mode: 0o600 });
}

function readHidden(prompt) {
  return new Promise((resolve) => {
    process.stdout.write(prompt);
    process.stdin.setRawMode?.(true);
    process.stdin.resume();
    process.stdin.setEncoding("utf8");
    let pw = "";
    const onData = (chunk) => {
      for (const c of chunk) {
        const code = c.charCodeAt(0);
        if (c === "\r" || c === "\n") {
          process.stdin.setRawMode?.(false); process.stdin.pause();
          process.stdin.off("data", onData); process.stdout.write("\n"); return resolve(pw);
        }
        if (code === 3) process.exit(130);              // Ctrl-C
        if (code === 127 || code === 8) pw = pw.slice(0, -1); // backspace
        else pw += c;
      }
    };
    process.stdin.on("data", onData);
  });
}

async function ask(prompt) {
  process.stdout.write(prompt);
  for await (const chunk of process.stdin) return chunk.toString().trim();
  return "";
}

const args = process.argv.slice(2);

if (args[0] === "--list") {
  const users = read();
  if (!users.length) { console.log("(no users)"); process.exit(0); }
  for (const u of users) console.log(`${u.username}\t${u.role}`);
  process.exit(0);
}

if (args[0] === "--delete") {
  const name = args[1];
  if (!name) { console.error("usage: --delete <username>"); process.exit(1); }
  const users = read().filter((u) => u.username !== name);
  write(users);
  console.log(`Removed ${name} (if present). ${users.length} user(s) remain.`);
  process.exit(0);
}

// Interactive add/update.
const username = await ask("Username: ");
if (!username) { console.error("username required"); process.exit(1); }
const role = (await ask(`Role [${ROLES.join("/")}] (default analyst): `)) || "analyst";
if (!ROLES.includes(role)) { console.error(`role must be one of ${ROLES.join(", ")}`); process.exit(1); }
const pw = await readHidden("Password (hidden): ");
if (pw.length < 8) { console.error("password must be at least 8 characters"); process.exit(1); }

const users = read().filter((u) => u.username !== username);
users.push({ username, role, hash: hashPassword(pw) });
write(users);
console.log(`\nSaved ${username} (${role}) to ${FILE}. ${users.length} user(s) total.`);
