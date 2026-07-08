import { FormEvent, useState } from "react";
import { login } from "../api";

export function Login({ onLogin }: { onLogin: (user: string) => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    login(username, password)
      .then((r) => onLogin(r.user))
      .catch((err) => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setBusy(false));
  };

  return (
    <div className="login-wrap">
      <form className="login panel" onSubmit={submit}>
        <div className="brand"><span className="dot" /> Detection Lab</div>
        <p className="muted">Sign in to view the ATT&amp;CK dashboard.</p>
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
      </form>
    </div>
  );
}
