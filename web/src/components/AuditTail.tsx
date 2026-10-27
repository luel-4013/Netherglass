import type { AuditPage } from "../types";

interface Props {
  audit: AuditPage | null;
}

export default function AuditTail({ audit }: Props) {
  return (
    <section className="panel panel-wide">
      <h2>
        AUDIT LOG{" "}
        {audit &&
          (audit.chain_valid ? (
            <span className="up">chain verified ({audit.chain_length})</span>
          ) : (
            <span className="down">CHAIN BROKEN</span>
          ))}
      </h2>
      <table className="tbl">
        <thead>
          <tr>
            <th>ID</th>
            <th>TS</th>
            <th>ACTOR</th>
            <th>ACTION</th>
            <th>TARGET</th>
            <th>HASH</th>
          </tr>
        </thead>
        <tbody>
          {audit?.events.map((event) => (
            <tr key={event.id}>
              <td>{event.id}</td>
              <td>{event.ts}</td>
              <td>{event.actor}</td>
              <td>{event.action}</td>
              <td>{event.target ?? "-"}</td>
              <td className="dim">{event.hash.slice(0, 12)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
