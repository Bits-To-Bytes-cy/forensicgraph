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

export type Evidence = {
  id: string;
  case_id: string;
  organization_id: string;
  evidence_number: number;
  original_filename: string;
  media_type: string;
  size_bytes: number;
  sha256: string;
  sha512: string;
  status: string;
  created_by: string;
  created_at: string;
  updated_at: string;
  verified_at: string | null;
};

export type EvidenceUpload = {
  id: string;
  case_id: string;
  original_filename: string;
  media_type: string;
  expected_size: number | null;
  bytes_received: number;
  status: string;
  created_at: string;
  updated_at: string;
};

export type IntegrityCheck = {
  id: string;
  evidence_id: string;
  sha256: string;
  sha512: string;
  size_bytes: number;
  storage_readback: boolean;
  hashes_match: boolean;
  chain_valid: boolean;
  details: string;
  checked_at: string;
};

export type CustodyEvent = {
  id: string;
  evidence_id: string;
  sequence_number: number;
  event_type: string;
  actor_id: string;
  occurred_at: string;
  payload: string;
  previous_hash: string | null;
  event_hash: string;
};

export type EvidenceDerivative = {
  id: string;
  evidence_id: string;
  original_filename: string;
  media_type: string;
  purpose: string;
  size_bytes: number;
  sha256: string;
  sha512: string;
  created_by: string;
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

function uploadContent(
  path: string,
  file: File,
  onProgress: (progress: number) => void,
): Promise<EvidenceUpload> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("PUT", `/api/v1${path}`);
    xhr.setRequestHeader(
      "Authorization",
      `Bearer ${localStorage.getItem("forensicgraph_access_token") ?? ""}`,
    );
    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable)
        onProgress(Math.round((event.loaded / event.total) * 100));
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300)
        resolve(JSON.parse(xhr.responseText));
      else
        reject(
          new Error(JSON.parse(xhr.responseText).detail ?? "Upload failed"),
        );
    };
    xhr.onerror = () => reject(new Error("Upload failed"));
    const form = new FormData();
    form.append("file", file);
    xhr.send(form);
  });
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
  evidence: (caseId: string) =>
    request<Evidence[]>(`/cases/${caseId}/evidence`),
  startEvidenceUpload: (caseId: string, body: object) =>
    request<EvidenceUpload>(`/cases/${caseId}/evidence/uploads`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  uploadEvidenceContent: (
    uploadId: string,
    file: File,
    onProgress: (progress: number) => void,
  ) => uploadContent(`/evidence/uploads/${uploadId}/content`, file, onProgress),
  completeEvidenceUpload: (uploadId: string) =>
    request<Evidence>(`/evidence/uploads/${uploadId}/complete`, {
      method: "POST",
    }),
  verifyEvidence: (evidenceId: string) =>
    request<IntegrityCheck>(`/evidence/${evidenceId}/verify`, {
      method: "POST",
    }),
  custody: (evidenceId: string) =>
    request<CustodyEvent[]>(`/evidence/${evidenceId}/custody`),
  derivatives: (evidenceId: string) =>
    request<EvidenceDerivative[]>(`/evidence/${evidenceId}/derivatives`),
};
