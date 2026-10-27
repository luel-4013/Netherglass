import { useCallback, useEffect, useState } from "react";
import {
  addCaseItem,
  createCase,
  getCase,
  getCases,
  removeCaseItem,
  updateCase,
} from "../api";
import { fmtTime } from "../format";
import type { CaseRow, SessionInfo } from "../types";

interface Props {
  captureId: string;
  session: SessionInfo;
}

const ITEM_TYPES = ["note", "finding", "evidence", "host", "domain"];

export default function CasesView({ captureId, session }: Props) {
  const [cases, setCases] = useState<CaseRow[]>([]);
  const [selected, setSelected] = useState<CaseRow | null>(null);
  const [title, setTitle] = useState("");
  const [summary, setSummary] = useState("");
  const [itemType, setItemType] = useState("note");
  const [itemId, setItemId] = useState("");
  const [itemNote, setItemNote] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const canEdit =
    session.user?.role === "admin" || session.user?.role === "analyst";

  const load = useCallback(async () => {
    try {
      const data = await getCases();
      setCases(data.cases);
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to load cases");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function open(caseId: string) {
    try {
      setSelected(await getCase(caseId));
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to load case");
    }
  }

  async function handleCreate() {
    if (title.trim().length < 3) {
      setError("case title must be at least 3 characters");
      return;
    }
    setBusy(true);
    try {
      const created = await createCase(title.trim(), summary.trim());
      setTitle("");
      setSummary("");
      setSelected(created);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to create case");
    } finally {
      setBusy(false);
    }
  }

  async function handleAddItem() {
    if (!selected) return;
    if (itemType !== "note" && !itemId.trim()) {
      setError("item id is required for findings/evidence/hosts/domains");
      return;
    }
    setBusy(true);
    try {
      const updated = await addCaseItem(selected.id, {
        item_type: itemType,
        item_id: itemType === "note" ? `note-${Date.now()}` : itemId.trim(),
        capture_id: captureId,
        note: itemNote.trim() || undefined,
      });
      setSelected(updated);
      setItemId("");
      setItemNote("");
      await load();
      setError("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to add item");
    } finally {
      setBusy(false);
    }
  }

  async function toggleStatus() {
    if (!selected) return;
    try {
      const updated = await updateCase(selected.id, {
        status: selected.status === "OPEN" ? "CLOSED" : "OPEN",
      });
      setSelected(updated);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "failed to update case");
    }
  }

  return (
    <>
      <h2>INVESTIGATION CASES</h2>
      <p className="dim">
        cases group findings, evidence and notes for one investigation. every
        change is written to the audit log. auditors have read-only access.
      </p>
      {error && <div className="error-bar">!! {error}</div>}

      {canEdit && (
        <div className="filterbar">
          <input
            placeholder="case title"
            value={title}
            onChange={(event) => setTitle(event.target.value)}
          />
          <input
            placeholder="summary (optional)"
            value={summary}
            onChange={(event) => setSummary(event.target.value)}
          />
          <button className="btn btn-small" onClick={() => void handleCreate()} disabled={busy}>
            [ OPEN CASE ]
          </button>
        </div>
      )}

      <table className="tbl">
        <thead>
          <tr>
            <th>ID</th>
            <th>TITLE</th>
            <th>STATUS</th>
            <th>ITEMS</th>
            <th>CREATED BY</th>
            <th>CREATED</th>
          </tr>
        </thead>
        <tbody>
          {cases.map((item) => (
            <tr
              key={item.id}
              style={{ cursor: "pointer" }}
              className={selected?.id === item.id ? "selected" : ""}
              onClick={() => void open(item.id)}
            >
              <td className="accent">{item.id}</td>
              <td>{item.title}</td>
              <td className={item.status === "OPEN" ? "up" : "dim"}>{item.status}</td>
              <td>{item.item_count ?? 0}</td>
              <td className="dim">{item.created_by}</td>
              <td className="mono-small">{item.created_at}</td>
            </tr>
          ))}
          {cases.length === 0 && (
            <tr>
              <td colSpan={6} className="dim">
                no cases yet
              </td>
            </tr>
          )}
        </tbody>
      </table>

      {selected && (
        <section className="panel">
          <h2>
            {selected.id} — {selected.title}{" "}
            <span className={selected.status === "OPEN" ? "up" : "dim"}>
              [{selected.status}]
            </span>
          </h2>
          {selected.summary && <p className="dim">{selected.summary}</p>}
          {canEdit && (
            <>
              <div className="filterbar">
                <select
                  value={itemType}
                  onChange={(event) => setItemType(event.target.value)}
                >
                  {ITEM_TYPES.map((item) => (
                    <option key={item} value={item}>
                      {item}
                    </option>
                  ))}
                </select>
                <input
                  placeholder={
                    itemType === "note" ? "note text (below)" : `${itemType} id`
                  }
                  value={itemId}
                  disabled={itemType === "note"}
                  onChange={(event) => setItemId(event.target.value)}
                />
                <input
                  placeholder="note (optional)"
                  value={itemNote}
                  onChange={(event) => setItemNote(event.target.value)}
                />
                <button
                  className="btn btn-small"
                  onClick={() => void handleAddItem()}
                  disabled={busy}
                >
                  [ ADD ]
                </button>
                <button className="btn btn-small" onClick={() => void toggleStatus()}>
                  [ {selected.status === "OPEN" ? "CLOSE" : "REOPEN"} ]
                </button>
              </div>
            </>
          )}
          <table className="tbl">
            <thead>
              <tr>
                <th>TYPE</th>
                <th>ITEM</th>
                <th>NOTE</th>
                <th>ADDED BY</th>
                <th>ADDED</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {selected.items?.map((item) => (
                <tr key={item.id}>
                  <td className="accent">{item.item_type}</td>
                  <td className="mono-small">{item.item_id}</td>
                  <td className="dim">{item.note ?? "-"}</td>
                  <td className="dim">{item.added_by}</td>
                  <td className="mono-small">{item.added_at}</td>
                  <td>
                    {canEdit && (
                      <button
                        className="btn btn-small"
                        onClick={() =>
                          void removeCaseItem(selected.id, item.id).then(setSelected)
                        }
                      >
                        [ REMOVE ]
                      </button>
                    )}
                  </td>
                </tr>
              ))}
              {selected.items?.length === 0 && (
                <tr>
                  <td colSpan={6} className="dim">
                    no items in this case
                  </td>
                </tr>
              )}
            </tbody>
          </table>
          {selected.timeline && selected.timeline.length > 0 && (
            <>
              <h2>CASE TIMELINE</h2>
              <table className="tbl">
                <thead>
                  <tr>
                    <th>TIME</th>
                    <th>KIND</th>
                    <th>EVENT</th>
                    <th>DETAIL</th>
                  </tr>
                </thead>
                <tbody>
                  {selected.timeline.map((event, index) => (
                    <tr key={index}>
                      <td className="mono-small">{fmtTime(event.ts)}</td>
                      <td className="accent">{event.kind}</td>
                      <td>{event.title}</td>
                      <td className="dim">{event.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </section>
      )}
    </>
  );
}
