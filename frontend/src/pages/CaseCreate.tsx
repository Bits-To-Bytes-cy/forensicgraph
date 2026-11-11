import { FormEvent, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate, useParams } from "react-router-dom";
import { api } from "../api";

export default function CaseCreate() {
  const { organizationId = "" } = useParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [form, setForm] = useState({
    title: "",
    description: "",
    scope: "",
    priority: "medium",
  });
  const mutation = useMutation({
    mutationFn: () => api.createCase(organizationId, form),
    onSuccess: (item) => {
      queryClient.invalidateQueries({ queryKey: ["cases", organizationId] });
      navigate(`/cases/${item.id}`);
    },
  });
  function submit(event: FormEvent) {
    event.preventDefault();
    mutation.mutate();
  }
  return (
    <section className="page narrow">
      <p className="eyebrow">NEW INVESTIGATION</p>
      <h2>Create case</h2>
      <form className="form-card" onSubmit={submit}>
        <label>
          Title
          <input
            required
            value={form.title}
            onChange={(e) => setForm({ ...form, title: e.target.value })}
          />
        </label>
        <label>
          Description
          <textarea
            value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
          />
        </label>
        <label>
          Scope
          <textarea
            value={form.scope}
            onChange={(e) => setForm({ ...form, scope: e.target.value })}
          />
        </label>
        <label>
          Priority
          <select
            value={form.priority}
            onChange={(e) => setForm({ ...form, priority: e.target.value })}
          >
            <option>low</option>
            <option>medium</option>
            <option>high</option>
            <option>critical</option>
          </select>
        </label>
        {mutation.isError && <p className="error">{mutation.error.message}</p>}
        <button className="button" disabled={mutation.isPending}>
          {mutation.isPending ? "Creating..." : "Create case"}
        </button>
      </form>
    </section>
  );
}
