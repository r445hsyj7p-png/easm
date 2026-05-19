import { useState, useEffect, useCallback, useRef } from "react";
import { apiFetch } from "../api/client";

const DEFAULT_PAGE_SIZE = 25;

/* Server-side paginated + filtered table.
   endpoint: e.g. "/tenants/xxx/targets"
   The API must accept: ?page=N&page_size=M&<filterKey>=<val>…
   and return: { items: [], total: N, page: N, page_size: N } */
export function useServerDataTable(endpoint, initialFilters = {}) {
  const [items,      setItems]      = useState([]);
  const [total,      setTotal]      = useState(0);
  const [page,       setPage]       = useState(1);
  const [pageSize]                  = useState(DEFAULT_PAGE_SIZE);
  const [filters,    setFilters]    = useState(initialFilters);
  const [loading,    setLoading]    = useState(false);
  const [error,      setError]      = useState(null);
  const abortRef                    = useRef(null);

  const fetch = useCallback(async (pg, flt) => {
    if (!endpoint) return;
    if (abortRef.current) abortRef.current.abort();
    abortRef.current = new AbortController();

    setLoading(true); setError(null);
    try {
      const params = new URLSearchParams({ page: pg, page_size: pageSize });
      for (const [k, v] of Object.entries(flt)) {
        if (v !== null && v !== undefined && v !== "" && v !== "ALL") params.set(k, v);
      }
      const data = await apiFetch(`${endpoint}?${params}`);
      setItems(data.items ?? data);
      setTotal(data.total ?? (data.items ?? data).length);
    } catch (e) {
      if (e.name !== "AbortError") setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [endpoint, pageSize]);

  useEffect(() => { fetch(page, filters); }, [fetch, page, filters]);

  const updateFilter = useCallback((key, value) => {
    setPage(1);
    setFilters(prev => ({ ...prev, [key]: value }));
  }, []);

  const resetFilters = useCallback(() => {
    setPage(1);
    setFilters(initialFilters);
  }, [initialFilters]);

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return {
    items, total, page, pageSize, totalPages,
    loading, error,
    filters,
    setPage,
    updateFilter,
    resetFilters,
    reload: () => fetch(page, filters),
  };
}
