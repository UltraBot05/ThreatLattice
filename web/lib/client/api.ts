"use client";

import { useCallback, useEffect, useState } from "react";

/**
 * Client-side fetch helpers for pages. Errors carry the API's
 * error.message so <ErrorState message={error} /> can show it as is.
 */
export class ClientApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
  ) {
    super(message);
  }
}

export async function api<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, {
    ...init,
    headers: { "Content-Type": "application/json", ...(init?.headers ?? {}) },
  });
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    const err = body?.error;
    throw new ClientApiError(res.status, err?.code ?? "DB_ERROR", err?.message ?? `Request failed (${res.status}).`);
  }
  return body as T;
}

/**
 * GET a URL (null = don't fetch yet). Re-fetches when the URL changes or on
 * reload(). While a new request is in flight, `data` keeps the previous
 * result so tables can animate from old rows to new ones.
 */
export function useApi<T>(url: string | null) {
  const [nonce, setNonce] = useState(0);
  const key = url === null ? null : `${url}#${nonce}`;
  const [res, setRes] = useState<{ key: string | null; data: T | null; error: string | null }>({
    key: null,
    data: null,
    error: null,
  });

  useEffect(() => {
    if (url === null || key === null) return;
    let alive = true;
    api<T>(url)
      .then((data) => alive && setRes({ key, data, error: null }))
      .catch((e: Error) => alive && setRes((r) => ({ key, data: r.data, error: e.message })));
    return () => {
      alive = false;
    };
  }, [url, key]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  const loading = key !== null && res.key !== key;
  return { data: res.data, error: loading ? null : res.error, loading, reload };
}
