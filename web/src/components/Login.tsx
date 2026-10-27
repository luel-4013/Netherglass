import { useState } from "react";
import { login } from "../api";
import type { SessionInfo } from "../types";

const BANNER = [
  "  _  _      _   _                _",
  " | \\| | ___| |_| |_  ___ _ _ __| |_ _ _ __ _ ___ ___",
  " | .` |/ -_)  _| ' \\/ -_) '_|_-<  _| '_/ _` (_-</ -_)",
  " |_|\\_|\\___|\\__|_||_\\___|_| /__/\\__|_| \\__,_/__/\\___|",
].join("\n");

interface Props {
  onLogin: (session: SessionInfo) => void;
}

export default function Login({ onLogin }: Props) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const session = await login(username, password);
      onLogin(session);
    } catch (err) {
      setError(err instanceof Error ? err.message : "login failed");
      setBusy(false);
    }
  }

  return (
    <div className="login-wrap">
      <form className="panel login-panel" onSubmit={(event) => void submit(event)}>
        <pre className="banner">{BANNER}</pre>
        <div className="login-sub">
          [ network visibility :: evidence vault :: internal use only ]
        </div>
        <label>
          OPERATOR ID
          <input
            autoFocus
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="username"
          />
        </label>
        <label>
          PASSPHRASE
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password"
          />
        </label>
        <button className="btn" disabled={busy || !username || !password}>
          {busy ? "AUTHENTICATING ..." : "[ AUTHENTICATE ]"}
        </button>
        {error && <div className="error">!! {error}</div>}
      </form>
    </div>
  );
}
