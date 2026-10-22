/**
 * Thin client for the AuthDock admin API.
 *
 * Every URL is derived from the page location instead of an absolute path, so
 * the app keeps working when a reverse proxy mounts it under a prefix
 * (code-server serves it at /proxy/<port>/admin/).
 */

const API_BASE = new URL('../api/admin/', window.location.href)
const LOGIN_URL = new URL('../login', window.location.href).href

/** An API failure carrying the server's machine code and human message. */
export class ApiError extends Error {
  readonly status: number
  readonly code: string

  constructor(status: number, code: string, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }
}

type ErrorBody = { ok?: boolean; code?: string; message?: string }

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/json')
  if (init.body !== undefined && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }

  const response = await fetch(new URL(path, API_BASE), {
    ...init,
    headers,
    credentials: 'same-origin',
  })

  let data: unknown = null
  try {
    data = await response.json()
  } catch {
    data = null
  }

  if (response.status === 401) {
    window.location.href = LOGIN_URL
    throw new ApiError(401, 'unauthenticated', '会话已过期，请重新登录')
  }

  const body = data as ErrorBody | null
  if (!response.ok || !body || body.ok === false) {
    throw new ApiError(
      response.status,
      body?.code ?? `http_${response.status}`,
      body?.message ?? `请求失败（HTTP ${response.status}）`,
    )
  }
  return data as T
}

// ── users ────────────────────────────────────────────────────────────────

export type Role = 'user' | 'admin'

export interface AdminUser {
  id: number
  username: string
  role: Role
  created_at: string
  /** True for the account that is signed in right now. */
  self: boolean
}

export interface UserInput {
  username: string
  password: string
  role: Role
}

export interface UserUpdate {
  role?: Role
  password?: string
}

export async function listUsers(signal?: AbortSignal): Promise<AdminUser[]> {
  const data = await request<{ users?: AdminUser[] }>('users', { signal })
  return data.users ?? []
}

export function createUser(input: UserInput): Promise<{ user: AdminUser }> {
  return request<{ user: AdminUser }>('users', { method: 'POST', body: JSON.stringify(input) })
}

export function updateUser(
  id: number,
  input: UserUpdate,
): Promise<{ user: AdminUser; logged_out?: boolean }> {
  return request<{ user: AdminUser; logged_out?: boolean }>(`users/${id}`, {
    method: 'PATCH',
    body: JSON.stringify(input),
  })
}

export function deleteUser(id: number): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`users/${id}`, { method: 'DELETE' })
}

// ── gates ────────────────────────────────────────────────────────────────

export interface Gate {
  id: number
  name: string
  /** Upstream address, e.g. "10.0.0.1:1234" or "http://10.0.0.1:1234". */
  from: string
  /** Subdomain label on the gateway domain. */
  to_prefix: string
  /** Path prefix in front of the forwarded path; may be empty. */
  to_suffix: string
  /** null means every account may use the gate; a value restricts it. */
  user_id: number | null
  /** Owner name when user_id is set, empty for a global gate. */
  username: string
  created_at: string
}

export interface GateInput {
  name: string
  from: string
  to_prefix: string
  to_suffix: string
  /** null (or omitted) = global, a user id = scoped to that account. */
  user_id: number | null
}

export interface GateList {
  gatewayDomain: string
  gates: Gate[]
}

export async function listGates(signal?: AbortSignal): Promise<GateList> {
  const data = await request<{ gateway_domain?: string; gates?: Gate[] }>('gates', { signal })
  return { gatewayDomain: data.gateway_domain ?? '', gates: data.gates ?? [] }
}

export function createGate(input: GateInput): Promise<{ gate: Gate }> {
  return request<{ gate: Gate }>('gates', { method: 'POST', body: JSON.stringify(input) })
}

export function updateGate(id: number, input: GateInput): Promise<{ gate: Gate }> {
  return request<{ gate: Gate }>(`gates/${id}`, { method: 'PATCH', body: JSON.stringify(input) })
}

export function deleteGate(id: number): Promise<{ ok: boolean }> {
  return request<{ ok: boolean }>(`gates/${id}`, { method: 'DELETE' })
}

// ── settings ─────────────────────────────────────────────────────────────

export interface Settings {
  gateway_domain: string
}

export async function getSettings(signal?: AbortSignal): Promise<Settings> {
  const data = await request<{ settings?: Settings }>('settings', { signal })
  return { gateway_domain: data.settings?.gateway_domain ?? '' }
}

export async function saveSettings(input: Settings): Promise<Settings> {
  const data = await request<{ settings?: Settings }>('settings', {
    method: 'PUT',
    body: JSON.stringify(input),
  })
  return { gateway_domain: data.settings?.gateway_domain ?? '' }
}

// ── session ──────────────────────────────────────────────────────────────

export function logout(): void {
  const url = new URL('../api/auth/logout', window.location.href)
  fetch(url, { method: 'POST', credentials: 'same-origin' })
    .catch(() => {
      // The redirect below is what matters; a failed call still ends the visit.
    })
    .finally(() => {
      window.location.href = LOGIN_URL
    })
}

export { LOGIN_URL }
