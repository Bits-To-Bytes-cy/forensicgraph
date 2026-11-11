export type Case = {
  id: string;
  organization_id: string;
  case_number: number;
  title: string;
  description: string;
  scope: string;
  priority: string;
  status: string;
  created_by: string;
  created_at: string;
  updated_at: string;
  closed_at: string | null;
  archived_at: string | null;
};

export type CaseMember = {
  user_id: string;
  email: string;
  display_name: string;
  role: string;
  created_at: string;
};

export type CaseHistory = {
  id: string;
  case_id: string;
  from_status: string | null;
  to_status: string;
  changed_by: string;
  created_at: string;
};

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api/v1${path}`, {
    ...init,
    headers: {
      "content-type": "application/json",
      Authorization: `Bearer ${localStorage.getItem("forensicgraph_access_token") ?? ""}`,
      ...init?.headers,
    },
  });
  if (!response.ok)
    throw new Error((await response.json()).detail ?? "Request failed");
  return response.status === 204 ? (undefined as T) : response.json();
}

export const api = {
  cases: (organizationId: string) =>
    request<Case[]>(`/organizations/${organizationId}/cases`),
  case: (caseId: string) => request<Case>(`/cases/${caseId}`),
  createCase: (organizationId: string, body: object) =>
    request<Case>(`/organizations/${organizationId}/cases`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateCase: (caseId: string, body: object) =>
    request<Case>(`/cases/${caseId}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  members: (caseId: string) =>
    request<CaseMember[]>(`/cases/${caseId}/members`),
  addMember: (caseId: string, body: object) =>
    request<CaseMember>(`/cases/${caseId}/members`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  removeMember: (caseId: string, userId: string) =>
    request<void>(`/cases/${caseId}/members/${userId}`, { method: "DELETE" }),
  status: (caseId: string, status: string) =>
    request<Case>(`/cases/${caseId}/status`, {
      method: "POST",
      body: JSON.stringify({ status }),
    }),
  history: (caseId: string) =>
    request<CaseHistory[]>(`/cases/${caseId}/history`),
};
