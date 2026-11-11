import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api } from "../api";

type Props = { organizationId: string };

export default function CaseDashboard({ organizationId }: Props) {
  const cases = useQuery({
    queryKey: ["cases", organizationId],
    queryFn: () => api.cases(organizationId),
  });
  return (
    <section className="page">
      <div className="page-heading">
        <div>
          <p className="eyebrow">INVESTIGATIONS</p>
          <h2>Case dashboard</h2>
          <p className="muted">
            Organization-scoped investigations and workflow status.
          </p>
        </div>
        <Link
          className="button"
          to={`/organizations/${organizationId}/cases/new`}
        >
          New case
        </Link>
      </div>
      {cases.isLoading && <p className="muted">Loading cases...</p>}
      {cases.isError && <p className="error">{cases.error.message}</p>}
      <div className="case-grid">
        {cases.data?.map((item) => (
          <Link className="case-card" key={item.id} to={`/cases/${item.id}`}>
            <span className={`badge ${item.status}`}>
              {item.status.replaceAll("_", " ")}
            </span>
            <h3>
              FG-{String(item.case_number).padStart(5, "0")} · {item.title}
            </h3>
            <p>{item.description || "No description provided."}</p>
            <small>
              {item.priority} priority · updated{" "}
              {new Date(item.updated_at).toLocaleDateString()}
            </small>
          </Link>
        ))}
      </div>
    </section>
  );
}
