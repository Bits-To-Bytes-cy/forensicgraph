import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, Evidence } from "../api";

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  return `${(bytes / 1024 / 1024).toFixed(2)} MB`;
}

export default function EvidenceVault() {
  const { caseId = "" } = useParams();
  const queryClient = useQueryClient();
  const [file, setFile] = useState<File | null>(null);
  const [progress, setProgress] = useState(0);
  const [selected, setSelected] = useState<Evidence | null>(null);
  const evidence = useQuery({
    queryKey: ["evidence", caseId],
    queryFn: () => api.evidence(caseId),
  });
  const custody = useQuery({
    queryKey: ["custody", selected?.id],
    queryFn: () => api.custody(selected!.id),
    enabled: Boolean(selected),
  });
  const derivatives = useQuery({
    queryKey: ["derivatives", selected?.id],
    queryFn: () => api.derivatives(selected!.id),
    enabled: Boolean(selected),
  });
  const upload = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error("Choose an evidence file");
      const session = await api.startEvidenceUpload(caseId, {
        original_filename: file.name,
        media_type: file.type || "application/octet-stream",
        expected_size: file.size,
      });
      await api.uploadEvidenceContent(session.id, file, setProgress);
      return api.completeEvidenceUpload(session.id);
    },
    onSuccess: () => {
      setFile(null);
      setProgress(0);
      queryClient.invalidateQueries({ queryKey: ["evidence", caseId] });
    },
  });
  const verify = useMutation({
    mutationFn: (id: string) => api.verifyEvidence(id),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ["evidence", caseId] }),
  });

  return (
    <section className="page">
      <Link to={`/cases/${caseId}`} className="back">
        ← Case details
      </Link>
      <div className="page-heading">
        <div>
          <p className="eyebrow">EVIDENCE VAULT</p>
          <h2>Original evidence inventory</h2>
          <p className="muted">
            Immutable originals, independently verifiable hashes, and a chained
            custody record.
          </p>
        </div>
      </div>
      <article className="panel upload-panel">
        <h3>Secure upload</h3>
        <input
          type="file"
          onChange={(event) => setFile(event.target.files?.[0] ?? null)}
        />
        <button
          className="button"
          onClick={() => upload.mutate()}
          disabled={!file || upload.isPending}
        >
          {upload.isPending ? `Uploading ${progress}%` : "Upload to quarantine"}
        </button>
        {upload.isPending && <progress value={progress} max="100" />}
        {upload.isError && <p className="error">{upload.error.message}</p>}
      </article>
      <div className="evidence-layout">
        <article className="panel">
          <h3>Inventory</h3>
          {evidence.isLoading && <p className="muted">Loading evidence...</p>}
          {evidence.data?.map((item) => (
            <button
              className={`evidence-row ${selected?.id === item.id ? "selected" : ""}`}
              key={item.id}
              onClick={() => setSelected(item)}
            >
              <span>
                <b>
                  EV-{String(item.evidence_number).padStart(5, "0")} ·{" "}
                  {item.original_filename}
                </b>
                <small>
                  {formatBytes(item.size_bytes)} · {item.media_type}
                </small>
              </span>
              <span className="badge">
                {item.verified_at ? "verified" : "unverified"}
              </span>
            </button>
          ))}
        </article>
        <article className="panel">
          {!selected && (
            <p className="muted">
              Select evidence to inspect hashes and custody.
            </p>
          )}
          {selected && (
            <>
              <h3>{selected.original_filename}</h3>
              <button
                className="button secondary"
                onClick={() => verify.mutate(selected.id)}
                disabled={verify.isPending}
              >
                Verify original and TrustLedger
              </button>
              <dl className="hash-list">
                <dt>SHA-256</dt>
                <dd>{selected.sha256}</dd>
                <dt>SHA-512</dt>
                <dd>{selected.sha512}</dd>
              </dl>
              <h3>Custody timeline</h3>
              {custody.data?.map((event) => (
                <div className="history-row" key={event.id}>
                  <span>{new Date(event.occurred_at).toLocaleString()}</span>
                  <b>{event.event_type}</b>
                  <small>#{event.sequence_number}</small>
                </div>
              ))}
              <h3>Working copies</h3>
              {derivatives.data?.map((derivative) => (
                <div className="history-row" key={derivative.id}>
                  <b>{derivative.original_filename}</b>
                  <small>{derivative.purpose}</small>
                </div>
              ))}
            </>
          )}
        </article>
      </div>
    </section>
  );
}
