import type { Finding, Report } from "@/lib/types";

function Chip({ label, value }: { label: string; value: string | boolean | null | undefined }) {
  const text = value === true ? "yes" : value === false ? "no" : value || "absent";
  const tone =
    value === "fail" || value === "softfail" || value === false
      ? "bad"
      : value === "pass" || value === true
        ? "good"
        : "";
  return <span className={`chip ${tone}`}>{`${label} ${text}`}</span>;
}

function FindingList({ items }: { items: Finding[] }) {
  return (
    <>
      {items.map((finding) => (
        <article className="finding" key={finding.id}>
          <h3>
            <span className={`sev ${finding.severity}`}>{finding.severity}</span>
            {finding.title}
          </h3>
          <p>{finding.explanation}</p>
          {finding.evidence.length > 0 && (
            <ul className="evidence">
              {finding.evidence.map((item, index) => (
                <li key={index}>{item}</li>
              ))}
            </ul>
          )}
        </article>
      ))}
    </>
  );
}

export function ReportView({ report, source }: { report: Report; source?: string }) {
  const { message, authentication: auth, identity } = report;
  const from = message.from;
  const rows: [string, string][] = [
    ["Subject", message.subject ?? ""],
    ["From", from ? (from.display ? `${from.display} <${from.email}>` : from.email) : ""],
    ["Reply-To", (message.reply_to ?? []).map((a) => a.email).join(", ")],
    ["Return-Path", message.return_path ?? ""],
    ["Date", message.date ?? ""],
  ];

  return (
    <section className="report" aria-live="polite">
      <div className={`banner ${report.verdict}`}>
        <p className={`verdict ${report.verdict}`}>{report.verdict}</p>
        <p>{report.summary}</p>
        <p className="action">{report.recommended_action}</p>
      </div>

      <h2>Message</h2>
      <table>
        <tbody>
          {rows.map(([label, value]) => (
            <tr key={label}>
              <th>{label}</th>
              <td>{value || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>Body</h2>
      {message.body ? (
        <>
          <p className="muted">
            {message.body_source === "html"
              ? "Visible text of the HTML part. The HTML itself is not rendered."
              : "Plain-text part. Any HTML is not rendered."}
          </p>
          <pre className="body">{message.body}</pre>
        </>
      ) : (
        <p>No readable body.</p>
      )}
      {source && (
        <details className="raw">
          <summary>Raw source</summary>
          <pre className="body">{source}</pre>
        </details>
      )}

      <h2>Authentication</h2>
      <div className="chips">
        <Chip label="authserv" value={auth.authserv_id || "none"} />
        <Chip label="trusted stamp" value={!!auth.header_trusted} />
        <Chip label="SPF" value={auth.spf} />
        <Chip label="DKIM" value={auth.dkim} />
        <Chip label="DMARC" value={auth.dmarc} />
        <Chip label="aligned" value={!!auth.aligned} />
        {auth.mailfrom_domain && <span className="chip">mailfrom {auth.mailfrom_domain}</span>}
        {(auth.dkim_signatures ?? []).map((sig, index) => (
          <span key={index} className={`chip ${sig.result === "pass" ? "good" : sig.result === "fail" ? "bad" : ""}`}>
            dkim {sig.result} d={sig.domain || "absent"}
          </span>
        ))}
      </div>
      <p className="muted">
        Sender treated as a known party: {identity.sender_trusted ? "yes" : "no"}. Reply-To on another domain:{" "}
        {identity.reply_to_mismatch ? "yes" : "no"}.
      </p>

      <h2>Findings</h2>
      {report.findings.length ? <FindingList items={report.findings} /> : <p>No material findings.</p>}

      {report.notes.length > 0 && (
        <>
          <h2>Notes</h2>
          <FindingList items={report.notes} />
        </>
      )}

      <h2>Links</h2>
      {report.links.length ? (
        <div className="scroll">
          <table>
            <thead>
              <tr>
                <th>Source</th>
                <th>Host</th>
                <th>Visible text</th>
                <th>Issues</th>
              </tr>
            </thead>
            <tbody>
              {report.links.map((link, index) => (
                <tr key={index}>
                  <td>{link.source}</td>
                  <td>{link.host || link.scheme || link.url}</td>
                  <td>{link.visible_text}</td>
                  <td>{link.issues.join("; ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p>No links.</p>
      )}

      <h2>Attachments</h2>
      {report.attachments.length ? (
        <table>
          <thead>
            <tr>
              <th>Filename</th>
              <th>Type</th>
              <th>Bytes</th>
              <th>Magic</th>
            </tr>
          </thead>
          <tbody>
            {report.attachments.map((item, index) => (
              <tr key={index}>
                <td>{item.filename || "(unnamed)"}</td>
                <td>{item.content_type}</td>
                <td>{item.size}</td>
                <td>{item.magic}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p>No attachments.</p>
      )}
    </section>
  );
}
