#!/usr/bin/env node
// Generate a DASH_PASSWORD_HASH value for dashboard/.env.
//
//   npm run hash-password            # prompts; input is not echoed
//   openssl rand -base64 24 | npm run hash-password   # or pipe one in
//
// Reads from stdin (never argv) so the password stays out of shell history.
import { hashPassword } from "../server/auth.js";

function readHiddenFromTTY() {
  return new Promise((resolve) => {
    process.stdout.write("Password (input hidden): ");
    process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding("utf8");
    let pw = "";
    const onData = (chunk) => {
      for (const c of chunk) {
        if (c === "\r" || c === "\n") {
          process.stdin.setRawMode(false);
          process.stdin.pause();
          process.stdin.off("data", onData);
          process.stdout.write("\n");
          return resolve(pw);
        }
        const code = c.charCodeAt(0);
        if (code === 3) process.exit(130); // Ctrl-C
        if (code === 127 || code === 8) pw = pw.slice(0, -1); // backspace
        else pw += c;
      }
    };
    process.stdin.on("data", onData);
  });
}

async function readPassword() {
  if (process.stdin.isTTY) return readHiddenFromTTY();
  let buf = "";
  for await (const chunk of process.stdin) buf += chunk;
  return buf.replace(/\r?\n$/, "");
}

const pw = await readPassword();
if (pw.length < 8) {
  console.error("Refusing to hash a password shorter than 8 characters.");
  process.exit(1);
}
console.log("\nAdd this line to dashboard/.env:\n");
console.log(`DASH_PASSWORD_HASH=${hashPassword(pw)}`);
