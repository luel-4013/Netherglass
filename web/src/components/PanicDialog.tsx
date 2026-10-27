import { useEffect, useState } from "react";

interface Props {
  open: boolean;
  onClose: () => void;
  onConfirm: (reason: string) => Promise<void>;
}

export default function PanicDialog({ open, onClose, onConfirm }: Props) {
  const [phrase, setPhrase] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!open) {
      setPhrase("");
      setReason("");
      setError("");
      setBusy(false);
    }
  }, [open]);

  if (!open) {
    return null;
  }

  async function confirm() {
    setBusy(true);
    setError("");
    try {
      await onConfirm(reason);
    } catch (err) {
      setError(err instanceof Error ? err.message : "emergency stop failed");
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop">
      <div className="panel modal">
        <h2 className="panic-title">EMERGENCY SECURITY STOP</h2>
        <ul className="panic-list">
          <li>
            stop packet capture? <span className="accent">YES</span>
          </li>
          <li>
            stop processing? <span className="accent">YES</span>
          </li>
          <li>
            stop active tests? <span className="accent">YES</span>
          </li>
          <li>
            stop exports? <span className="accent">YES</span>
          </li>
          <li>
            lock sensitive evidence? <span className="accent">YES</span>
          </li>
        </ul>
        <p className="dim">
          Evidence already collected is preserved and audited. Nothing restarts
          automatically; an authorized administrator must perform recovery.
        </p>
        <p className="dim">
          Type <span className="accent">EMERGENCY STOP</span> to confirm.
        </p>
        <input
          value={phrase}
          onChange={(event) => setPhrase(event.target.value)}
          placeholder="EMERGENCY STOP"
        />
        <input
          value={reason}
          onChange={(event) => setReason(event.target.value)}
          placeholder="reason (optional)"
        />
        {error && <div className="error">!! {error}</div>}
        <div className="modal-actions">
          <button className="btn" onClick={onClose} disabled={busy}>
            [ CANCEL ]
          </button>
          <button
            className="btn btn-panic"
            disabled={phrase.trim() !== "EMERGENCY STOP" || busy}
            onClick={() => void confirm()}
          >
            [ CONFIRM EMERGENCY STOP ]
          </button>
        </div>
      </div>
    </div>
  );
}
