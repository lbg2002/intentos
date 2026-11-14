/**
 * IntentOS Wave 2 — Trusted UI JSON-RPC & ModuleRpc Client
 * Communicates over `/api/rpc` with AbortSignal support and automatic stub/error fallback.
 */

let reqCounter = 0;

/**
 * Check whether a module_rpc response is an unimplemented placeholder stub.
 * @param {any} res
 * @returns {boolean}
 */
export function isStubResult(res) {
  if (!res || !res.ok) return true;
  if (res.result && typeof res.result === 'object' && res.result.status === 'stub') {
    return true;
  }
  return false;
}

/**
 * Invoke a top-level `UiRpcRequest` method over `/api/rpc`.
 * @param {string} method
 * @param {object} [params]
 * @param {{ signal?: AbortSignal }} [options]
 * @returns {Promise<{id: string, ok: boolean, result?: any, error?: string, aborted?: boolean}>}
 */
export async function rpc(method, params = undefined, options = {}) {
  reqCounter += 1;
  const id = `ui_${Date.now()}_${reqCounter}`;
  const body = params === undefined ? { id, method } : { id, method, params };
  try {
    const resp = await fetch('/api/rpc', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: options && options.signal ? options.signal : undefined,
    });
    if (!resp.ok) {
      return {
        id,
        ok: false,
        error: `HTTP ${resp.status}: ${resp.statusText}`,
      };
    }
    return await resp.json();
  } catch (err) {
    if (err && err.name === 'AbortError') {
      return {
        id,
        ok: false,
        aborted: true,
        error: '已取消当前请求',
      };
    }
    return {
      id,
      ok: false,
      error: err && err.message ? err.message : String(err),
    };
  }
}

/**
 * Invoke a modular domain RPC (`backend_bridge`, `memory_hub`, `app_adapter`, `intent_engine`, `config_center`, `execution_hub`, `web_ui`).
 * Automatically invokes `fallbackFn` when the domain returns an error OR a `{ status: "stub" }` placeholder.
 * @param {string} domain
 * @param {string} action
 * @param {object} [payload]
 * @param {Function|null} [fallbackFn]
 * @param {{ signal?: AbortSignal }} [options]
 * @returns {Promise<{id: string, ok: boolean, result?: any, error?: string, fallback?: boolean, aborted?: boolean}>}
 */
export async function moduleRpc(domain, action, payload = {}, fallbackFn = null, options = {}) {
  const res = await rpc(
    'module_rpc',
    {
      domain,
      action,
      payload: payload || {},
    },
    options
  );

  if (res && res.aborted) {
    return res;
  }

  if (res && res.ok && !isStubResult(res)) {
    return res;
  }

  if (typeof fallbackFn === 'function') {
    try {
      const reason = isStubResult(res) ? `${domain}.${action} returned stub` : (res ? res.error : 'module_rpc failed');
      const fbResult = await fallbackFn(reason);
      return {
        id: res ? res.id : `fb_${Date.now()}`,
        ok: true,
        result: fbResult,
        fallback: true,
      };
    } catch (fbErr) {
      return {
        id: res ? res.id : `fb_${Date.now()}`,
        ok: false,
        error: fbErr && fbErr.message ? fbErr.message : String(fbErr),
      };
    }
  }

  return res;
}

export const module_rpc = moduleRpc;
