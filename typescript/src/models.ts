// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

/** The subset of the server's VM record that is useful to callers; `raw` keeps all of it. */
export interface SandboxInfo {
  id: string;
  name: string;
  status: string;
  backend?: string;
  guestIp?: string;
  pid?: number;
  createdAt?: string;
  expiresAt?: string;
  /** Only present on create responses when a confidential mode was requested. */
  confidential?: Record<string, unknown>;
  raw: Record<string, unknown>;
}

export function sandboxInfoFromRecord(rec: Record<string, unknown>): SandboxInfo {
  const str = (k: string) => (typeof rec[k] === "string" ? (rec[k] as string) : undefined);
  return {
    id: String(rec.id),
    name: str("name") ?? "",
    status: str("status") ?? "",
    backend: str("backend"),
    guestIp: str("guest_ip"),
    pid: typeof rec.pid === "number" ? rec.pid : undefined,
    createdAt: str("created_at"),
    expiresAt: str("expires_at"),
    confidential: (rec.confidential as Record<string, unknown> | undefined) ?? undefined,
    raw: rec,
  };
}

/** Outcome of a command run through the guest agent. */
export interface ExecResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  /** True when the exit code is 0. */
  ok: boolean;
}

/** Result of recording a file baseline. */
export interface BaselineSummary {
  files: number;
  mode: string;
  paths: string[];
}

/** Files changed since the baseline. A rename is one deletion plus one addition. */
export interface ChangeSet {
  added: string[];
  modified: string[];
  deleted: string[];
  unchanged: number;
  /** Fingerprint used: `sha256`, or the `stat` size+mtime fallback. */
  mode: string;
  paths: string[];
  baselineTakenAtUnix: number;
  /** True when nothing was added, modified or deleted. */
  clean: boolean;
}

/** A guest file: raw bytes plus the Unix mode bits the guest reported. */
export interface FileContent {
  data: Uint8Array;
  mode: number;
}

/** A named persistent volume to attach (needs a QEMU-backed template). */
export interface Volume {
  name: string;
  guestPath: string;
  readOnly?: boolean;
}

/**
 * A response proxied from an HTTP service inside the guest. The proxy relays the
 * guest's own status codes, so a 4xx/5xx here is not thrown.
 */
export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
  ok: boolean;
  text(): string;
  json<T = unknown>(): T;
  /** Throws {@link ApiError} unless the status is 2xx. */
  raiseForStatus(): void;
}

export interface CreateSandboxOptions {
  name?: string;
  /** A template under the server's templates dir. */
  template?: string;
  /** A raw create spec, as accepted by `POST /v1/vms`. */
  spec?: Record<string, unknown>;
  ttlSeconds?: number;
  httpProxyPort?: number;
  httpProxyPorts?: number[];
  volumes?: Volume[];
  vcpus?: number;
  memoryMib?: number;
  confidential?: "auto" | "required";
  /** `{}` for defaults, or limits such as `{ timeout_seconds: 60 }`; needs `[sandbox.procbox] enabled = true`. */
  procbox?: Record<string, unknown>;
  timeoutMs?: number;
}
