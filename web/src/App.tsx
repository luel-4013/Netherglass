import { useEffect, useState } from "react";
import { getSession, setCsrf } from "./api";
import type { SessionInfo } from "./types";
import Dashboard from "./components/Dashboard";
import Login from "./components/Login";
import CaptureWorkspace from "./components/CaptureWorkspace";

const ANONYMOUS: SessionInfo = { authenticated: false, permissions: [] };

export default function App() {
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [bootError, setBootError] = useState("");
  const [openCapture, setOpenCapture] = useState<string | null>(null);

  useEffect(() => {
    getSession()
      .then((info) => {
        setCsrf(info.csrf_token ?? "");
        setSession(info);
      })
      .catch((err: unknown) =>
        setBootError(err instanceof Error ? err.message : String(err)),
      );
  }, []);

  if (bootError) {
    return <div className="boot">CONNECTION FAILED: {bootError}</div>;
  }
  if (!session) {
    return <div className="boot">NETHERGLASS :: establishing uplink ...</div>;
  }
  if (!session.authenticated) {
    return (
      <Login
        onLogin={(info) => {
          setCsrf(info.csrf_token ?? "");
          setSession(info);
        }}
      />
    );
  }
  if (openCapture) {
    return (
      <CaptureWorkspace
        captureId={openCapture}
        session={session}
        onBack={() => setOpenCapture(null)}
      />
    );
  }
  return (
    <Dashboard
      session={session}
      onOpenPackets={(captureId) => setOpenCapture(captureId)}
      onLogout={() => {
        setCsrf("");
        setSession(ANONYMOUS);
      }}
    />
  );
}
