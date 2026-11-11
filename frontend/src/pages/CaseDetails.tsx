import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";

export default function CaseDetails() {
  const { caseId = "" } = useParams();
  const queryClient = useQueryClient();
  const [memberId, setMemberId] = useState("");
  const [role, setRole] = useState("investigator");
  const item = useQuery({
    queryKey: ["case", caseId],
    queryFn: () => api.case(caseId),
  });
  const members = useQuery({
    queryKey: ["members", caseId],
    queryFn: () => api.members(caseId),
  });
  const history = useQuery({
    queryKey: ["history", caseId],
    queryFn: () => api.history(caseId),
  });
  const status = useMutation({
    mutationFn: (next: string) => api.status(caseId, next),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ["case", caseId] }),
  });
  const addMember = useMutation({
    mutationFn: () => api.addMember(caseId, { user_id: memberId, role }),
    onSuccess: () => {
      setMemberId("");
      queryClient.invalidateQueries({ queryKey: ["members", caseId] });
    },
  });
  if (item.isLoading)
    return (
      <main className="page">
        <p className="muted">Loading case...</p>
      </main>
    );
  if (item.isError || !item.data)
    return (
      <main className="page">
        <p className="error">Unable to load case.</p>
      </main>
    );
  const current = item.data;
  return (
    <section className="page">
      <Link to="/" className="back">
        ← Case dashboard
      </Link>
      <div className="page-heading">
        <div>
          <p className="eyebrow">
            FG-{String(current.case_number).padStart(5, "0")}
          </p>
          <h2>{current.title}</h2>
          <p className="muted">{current.description}</p>
        </div>
        <span className={`badge ${current.status}`}>
          {current.status.replaceAll("_", " ")}
        </span>
      </div>
      <div className="details-grid">
        <article className="panel">
          <h3>Case overview</h3>
          <dl>
            <dt>Priority</dt>
            <dd>{current.priority}</dd>
            <dt>Scope</dt>
            <dd>{current.scope || "Not specified"}</dd>
            <dt>Created</dt>
            <dd>{new Date(current.created_at).toLocaleString()}</dd>
          </dl>
          <h3>Workflow</h3>
          <div className="workflow-actions">
            {[
              "open",
              "under_investigation",
              "pending_review",
              "closed",
              "archived",
            ].map((next) => (
              <button
                className="button secondary"
                key={next}
                onClick={() => status.mutate(next)}
                disabled={status.isPending}
              >
                {next.replaceAll("_", " ")}
              </button>
            ))}
          </div>
        </article>
        <article className="panel">
          <h3>Case membership</h3>
          {members.data?.map((member) => (
            <div className="member-row" key={member.user_id}>
              <span>
                <b>{member.display_name}</b>
                <small>{member.email}</small>
              </span>
              <span className="badge">{member.role.replaceAll("_", " ")}</span>
            </div>
          ))}
          <div className="member-form">
            <input
              placeholder="User ID"
              value={memberId}
              onChange={(e) => setMemberId(e.target.value)}
            />
            <select value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="investigator">Investigator</option>
              <option value="reviewer">Reviewer</option>
              <option value="observer">Observer</option>
            </select>
            <button
              className="button"
              onClick={() => addMember.mutate()}
              disabled={!memberId || addMember.isPending}
            >
              Assign
            </button>
          </div>
          {addMember.isError && (
            <p className="error">{addMember.error.message}</p>
          )}
        </article>
      </div>
      <article className="panel">
        <h3>Investigation history</h3>
        {history.data?.map((entry) => (
          <div className="history-row" key={entry.id}>
            <span>{new Date(entry.created_at).toLocaleString()}</span>
            <b>
              {entry.from_status ?? "created"} → {entry.to_status}
            </b>
            <small>Actor {entry.changed_by}</small>
          </div>
        ))}
      </article>
    </section>
  );
}
