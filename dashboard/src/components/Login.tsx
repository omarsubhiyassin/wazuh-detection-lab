import { FormEvent, useState } from "react";
import type { Session } from "../types";
import { login } from "../api";

// Inline shield + live-pulse mark (no image files; tinted via CSS currentColor).
function ShieldMark() {
  return (
    <svg className="login-shield" viewBox="0 0 64 64" width="88" height="88"
      fill="none" aria-hidden="true">
      <path className="login-shield-fill"
        d="M32 5 L54 13 V32 C54 45 44 54 32 59 C20 54 10 45 10 32 V13 Z" />
      <path className="login-shield-edge"
        d="M32 5 L54 13 V32 C54 45 44 54 32 59 C20 54 10 45 10 32 V13 Z"
        strokeWidth="2.5" strokeLinejoin="round" />
      <polyline className="login-shield-pulse"
        points="16,33 25,33 29,24 34,42 38,33 48,33"
        strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function Login({ onLogin }: { onLogin: (s: Session) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    login(username, password)
      .then(onLogin)
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setBusy(false));
  };

  return (
    <div className="login-page">
      <aside className="login-brand">
        <div className="login-brand-inner">
          <ShieldMark />
          <h1 className="login-wordmark">Detection Lab</h1>
          <p className="login-tagline">MITRE ATT&amp;CK detection engineering &amp; SOC dashboard</p>
          <ul className="login-points">
            <li>Live alert triage across your fleet</li>
            <li>ATT&amp;CK coverage at a glance</li>
            <li>Role-based access with a full audit trail</li>
          </ul>
        </div>
      </aside>

      <main className="login-form-side">
        <form className="login-card" onSubmit={submit}>
          <div className="brand login-card-brand"><span className="dot" /> Detection Lab</div>
          <h2 className="login-heading">Sign in</h2>
          <p className="muted login-sub">Access the ATT&amp;CK dashboard.</p>
          {error && <div className="error">{error}</div>}
          <label>Username
            <input value={username} autoComplete="username" autoFocus
              onChange={(e) => setUsername(e.target.value)} />
          </label>
          <label>Password
            <input type="password" value={password} autoComplete="current-password"
              onChange={(e) => setPassword(e.target.value)} />
          </label>
          <button type="submit" disabled={busy || !username || !password}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
          <p className="login-foot muted">Authorized use only · sessions are audited</p>
        </form>
      </main>
    </div>
  );
}
