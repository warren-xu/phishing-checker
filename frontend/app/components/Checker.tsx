"use client";

import { useState } from "react";

import type { Report } from "@/lib/types";

import { ReportView } from "./ReportView";

// Vercel caps function request bodies at 4.5 MB; the backend caps at 4 MB.
const MAX_BYTES = 4_000_000;

async function readReport(response: Response): Promise<Report> {
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(body.detail || `The server rejected that message (${response.status}).`);
  }
  return body as Report;
}

async function analyzeDirect(body: BodyInit): Promise<Report> {
  return readReport(
    await fetch("/api/analyze", { method: "POST", headers: { "Content-Type": "message/rfc822" }, body }),
  );
}

export function Checker() {
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<Report | null>(null);
  const [source, setSource] = useState("");

  async function run(task: () => Promise<Report>, file: File) {
    setBusy(true);
    setStatus("Analyzing…");
    setReport(null);
    setSource("");
    try {
      const [result, text] = await Promise.all([task(), file.text()]);
      setSource(text);
      setReport(result);
      setStatus("");
    } catch (error) {
      setStatus((error as Error).message);
    } finally {
      setBusy(false);
    }
  }

  function pickFile(file: File) {
    if (file.size > MAX_BYTES) {
      setStatus(`${file.name} is ${(file.size / 1e6).toFixed(1)} MB. The limit is 4 MB.`);
      return;
    }
    run(() => analyzeDirect(file), file);
  }

  return (
    <main>
      <section className="panel">
        <p className="muted">Upload a raw .eml file, headers included. Up to 4 MB.</p>
        <div className="row">
          <label className="file">
            Upload .eml
            <input
              type="file"
              accept=".eml,message/rfc822"
              disabled={busy}
              onChange={(event) => {
                const file = event.target.files?.[0];
                event.target.value = "";
                if (file) pickFile(file);
              }}
            />
          </label>
        </div>
        <p className="status" role="status">
          {status}
        </p>
      </section>
      {report ? <ReportView report={report} source={source} /> : <section className="report empty" />}
    </main>
  );
}
