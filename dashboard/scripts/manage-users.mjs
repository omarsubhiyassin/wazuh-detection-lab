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

// Read one line from stdin without tearing the stream down, so several prompts
// work in sequence. (The old code used `for await (...) return`, whose iterator
// .return() destroyed process.stdin — the second prompt then failed with
// ABORT_ERR.) Raw mode with manual echo on a TTY; `hidden` suppresses the echo.
// Any bytes after the newline (piped multi-line input) are pushed back for the
// next read.
function readLine(prompt, { hidden = false } = {}) {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    process.stdout.write(prompt);
    stdin.setRawMode?.(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    let buf = "";
    const onData = (chunk) => {
      for (let i = 0; i < chunk.length; i++) {
        const c = chunk[i];
        const code = c.charCodeAt(0);
        if (c === "\n" || c === "\r") {
          const rest = chunk.slice(i + 1);
          stdin.off("data", onData);
          stdin.setRawMode?.(false);
          stdin.pause();
          if (rest.length) stdin.unshift(rest);
          process.stdout.write("\n");
          return resolve(buf);
        }
        if (code === 3) { process.stdout.write("\n"); process.exit(130); } // Ctrl-C
        else if (code === 127 || code === 8) {                             // backspace
          if (buf.length) { buf = buf.slice(0, -1); if (!hidden) process.stdout.write("\b \b"); }
        } else if (code >= 32) {                                           // printable
          buf += c;
          if (!hidden) process.stdout.write(c);
        }
      }
    };
    stdin.on("data", onData);
  });
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
const username = (await readLine("Username: ")).trim();
if (!username) { console.error("username required"); process.exit(1); }
const role = (await readLine(`Role [${ROLES.join("/")}] (default analyst): `)).trim() || "analyst";
if (!ROLES.includes(role)) { console.error(`role must be one of ${ROLES.join(", ")}`); process.exit(1); }
const pw = await readLine("Password (hidden): ", { hidden: true });
if (pw.length < 8) { console.error("password must be at least 8 characters"); process.exit(1); }

const users = read().filter((u) => u.username !== username);
users.push({ username, role, hash: hashPassword(pw) });
write(users);
console.log(`\nSaved ${username} (${role}) to ${FILE}. ${users.length} user(s) total.`);
