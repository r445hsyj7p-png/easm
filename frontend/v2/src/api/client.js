const API_BASE = "/api/v1";

export const getToken      = ()    => localStorage.getItem("easm_token") || "";
export const saveToken     = tok   => localStorage.setItem("easm_token", tok);
export const clearToken    = ()    => localStorage.removeItem("easm_token");
export const getTenantId   = ()    => localStorage.getItem("easm_tenant_id") || null;
export const saveTenantId  = tid   => localStorage.setItem("easm_tenant_id", tid);
export const clearTenantId = ()    => localStorage.removeItem("easm_tenant_id");

export async function apiFetch(path, opts = {}) {
  const token = getToken();
  const res = await fetch(API_BASE + path, {
    ...opts,
    headers: {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(opts.headers || {}),
    },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (res.status === 401) { clearToken(); clearTenantId(); window.location.reload(); throw new Error("401"); }
  if (!res.ok) {
    const e = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(e.detail || `HTTP ${res.status}`);
  }
  return res.json();
}
