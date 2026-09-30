// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

import {
  ApiError,
  AuthError,
  ConnectionFailed,
  ForbiddenError,
  NotFound,
  RateLimited,
  RequestTimeout,
} from "./errors.js";
import {
  BaselineSummary,
  ChangeSet,
  CreateSandboxOptions,
  ExecResult,
  FileContent,
  HttpResponse,
  SandboxInfo,
  sandboxInfoFromRecord,
} from "./models.js";

/** Mirrors fluxvm_guest_protocol::MAX_FILE_TRANSFER_BYTES: one base64 JSON line, nothing larger. */
export const MAX_FILE_TRANSFER_BYTES = 64 * 1024 * 1024;
/** Mirrors fluxvm_guest_protocol::DEFAULT_EXEC_TIMEOUT_SECS. */
export const DEFAULT_EXEC_TIMEOUT_SECS = 30;
/** The server waits `timeout_seconds + 5` for the guest agent; give the HTTP call more. */
const EXEC_HTTP_SLACK_MS = 10_000;

type Json = Record<string, unknown>;

export interface FluxVMOptions {
  /** e.g. `http://127.0.0.1:8080`. */
  baseUrl: string;
  /** Bearer token (static token or OIDC JWT). Omit only for an unauthenticated loopback server. */
  token?: string;
  /** Default per-request timeout in milliseconds. */
  timeoutMs?: number;
  /** Extra headers sent on every request (for example `X-Client-Cert-*` from a trusted mTLS frontend). */
  headers?: Record<string, string>;
  /** Replace `fetch`, for a custom TLS agent or for tests. */
  fetch?: typeof fetch;
}

interface Sent {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
}

function errorFromResponse(status: number, raw: Uint8Array, headers: Record<string, string>): ApiError {
  const text = new TextDecoder().decode(raw);
  let body: unknown = text;
  let message = text;
  try {
    const parsed: unknown = JSON.parse(text);
    body = parsed;
    if (parsed && typeof parsed === "object" && "error" in parsed) {
      message = String((parsed as Json).error);
    }
  } catch {
    // not JSON: keep the raw text
  }
  if (status === 401) return new AuthError(status, body, message);
  if (status === 403) return new ForbiddenError(status, body, message);
  if (status === 404) return new NotFound(status, body, message);
  // GET/DELETE /v1/vms/{id} answer an unknown VM with 400 "VM not found", not 404.
  if (status === 400 && message.trim().toLowerCase() === "vm not found") {
    return new NotFound(status, body, message);
  }
  if (status === 429) {
    const value = headers["retry-after"];
    const n = value === undefined ? NaN : Number(value);
    return new RateLimited(status, body, message, Number.isFinite(n) ? n : undefined);
  }
  return new ApiError(status, body, message);
}

/** Quote one argument for `/bin/sh -c`, like Python's `shlex.quote`. */
export function shellQuote(arg: string): string {
  if (arg === "") return "''";
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(arg)) return arg;
  return `'${arg.replace(/'/g, `'"'"'`)}'`;
}

const enc = encodeURIComponent;

/** Encode a path for the reverse-proxy routes, keeping the characters URLs allow unescaped. */
function encodeProxyPath(path: string): string {
  return path
    .replace(/^\/+/, "")
    .split("/")
    .map((seg) => enc(seg).replace(/%(24|26|2B|2C|3B|3D|3A|40)/g, (_, h: string) => String.fromCharCode(parseInt(h, 16))))
    .join("/");
}

function toB64(data: Uint8Array): string {
  return Buffer.from(data).toString("base64");
}

/** Client for one FluxVM API endpoint. */
export class FluxVM {
  readonly baseUrl: string;
  readonly token?: string;
  readonly timeoutMs: number;
  readonly headers: Record<string, string>;
  private readonly fetchFn: typeof fetch;

  constructor(opts: FluxVMOptions) {
    if (!opts.baseUrl) throw new Error("baseUrl is required");
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.token = opts.token;
    this.timeoutMs = opts.timeoutMs ?? 30_000;
    this.headers = { ...(opts.headers ?? {}) };
    this.fetchFn = opts.fetch ?? fetch;
  }

  /** One request; resolves for every HTTP status. Redirects are never followed. */
  async send(
    method: string,
    path: string,
    body?: Uint8Array | string,
    headers?: Record<string, string>,
    timeoutMs?: number,
  ): Promise<Sent> {
    const merged: Record<string, string> = { ...this.headers, ...(headers ?? {}) };
    if (this.token) merged["Authorization"] = `Bearer ${this.token}`;
    const ms = timeoutMs ?? this.timeoutMs;
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), ms);
    try {
      const resp = await this.fetchFn(this.baseUrl + path, {
        method,
        headers: merged,
        body: body as BodyInit | undefined,
        redirect: "manual",
        signal: ctl.signal,
      });
      const outHeaders: Record<string, string> = {};
      resp.headers.forEach((v, k) => {
        outHeaders[k.toLowerCase()] = v;
      });
      return { status: resp.status, headers: outHeaders, body: new Uint8Array(await resp.arrayBuffer()) };
    } catch (err) {
      if (ctl.signal.aborted) throw new RequestTimeout(`${method} ${path} timed out`);
      throw new ConnectionFailed(`${method} ${this.baseUrl}${path}: ${(err as Error).message}`);
    } finally {
      clearTimeout(timer);
    }
  }

  async json<T = any>(
    method: string,
    path: string,
    payload?: unknown,
    opts: { timeoutMs?: number; expect?: number[] } = {},
  ): Promise<T> {
    const headers: Record<string, string> = { Accept: "application/json" };
    let body: string | undefined;
    if (payload !== undefined) {
      body = JSON.stringify(payload);
      headers["Content-Type"] = "application/json";
    }
    const r = await this.send(method, path, body, headers, opts.timeoutMs);
    if (!(opts.expect ?? [200, 201]).includes(r.status)) {
      throw errorFromResponse(r.status, r.body, r.headers);
    }
    if (r.body.length === 0) return undefined as T;
    const text = new TextDecoder().decode(r.body);
    try {
      return JSON.parse(text) as T;
    } catch {
      throw new ApiError(r.status, text, "response was not JSON");
    }
  }

  /** `GET /healthz` (no auth needed). True when the server says ok. */
  async health(): Promise<boolean> {
    return Boolean((await this.json("GET", "/healthz"))?.ok);
  }

  /** `GET /v1/openapi.json` (no auth needed). */
  openapi(): Promise<Json> {
    return this.json("GET", "/v1/openapi.json");
  }

  /** `GET /v1/host/confidential`: what the host offers for confidential guests. */
  hostConfidential(): Promise<Json> {
    return this.json("GET", "/v1/host/confidential");
  }

  /** `POST /v1/sandboxes`. Options left undefined are omitted so the server's defaults apply. */
  async createSandbox(o: CreateSandboxOptions = {}): Promise<Sandbox> {
    if (o.confidential !== undefined && o.confidential !== "auto" && o.confidential !== "required") {
      throw new Error('confidential must be "auto" or "required"');
    }
    const payload: Json = {};
    const set = (k: string, v: unknown) => {
      if (v !== undefined) payload[k] = v;
    };
    set("name", o.name);
    set("template", o.template);
    set("spec", o.spec);
    set("ttl_seconds", o.ttlSeconds);
    set("http_proxy_port", o.httpProxyPort);
    set("http_proxy_ports", o.httpProxyPorts?.length ? o.httpProxyPorts : undefined);
    set(
      "volumes",
      o.volumes?.length
        ? o.volumes.map((v) => ({ name: v.name, guest_path: v.guestPath, read_only: v.readOnly ?? false }))
        : undefined,
    );
    set("vcpus", o.vcpus);
    set("memory_mib", o.memoryMib);
    set("confidential", o.confidential);
    set("procbox", o.procbox);
    if (o.gpus !== undefined && !(Number.isInteger(o.gpus) && o.gpus >= 0 && o.gpus <= 8)) {
      throw new RangeError("gpus must be an integer between 0 and 8");
    }
    set("gpus", o.gpus);
    const record = await this.json<Json>("POST", "/v1/sandboxes", payload, {
      timeoutMs: o.timeoutMs,
      expect: [201],
    });
    return new Sandbox(this, sandboxInfoFromRecord(record));
  }

  /** `GET /v1/sandboxes`: the caller's tenant's sandboxes. */
  async listSandboxes(): Promise<SandboxInfo[]> {
    const data = await this.json<{ items?: Json[] }>("GET", "/v1/sandboxes");
    return (data.items ?? []).map(sandboxInfoFromRecord);
  }

  /** Attach to an existing sandbox via `GET /v1/vms/{id}` (a sandbox is a VM record). */
  async getSandbox(id: string): Promise<Sandbox> {
    const record = await this.json<Json>("GET", `/v1/vms/${enc(id)}`);
    return new Sandbox(this, sandboxInfoFromRecord(record));
  }

  /** Create a sandbox, run `fn`, and delete the sandbox afterwards even if `fn` throws. */
  async withSandbox<T>(opts: CreateSandboxOptions, fn: (sb: Sandbox) => Promise<T>): Promise<T> {
    const sb = await this.createSandbox(opts);
    try {
      return await fn(sb);
    } finally {
      await sb.delete().catch((e) => {
        if (!(e instanceof NotFound)) throw e;
      });
    }
  }
}

/** A handle to one sandbox. */
export class Sandbox {
  info: SandboxInfo;

  constructor(private readonly client: FluxVM, info: SandboxInfo) {
    this.info = info;
  }

  get id(): string {
    return this.info.id;
  }

  private path(suffix: string): string {
    return `/v1/sandboxes/${enc(this.id)}${suffix}`;
  }

  /** Re-read the record (`GET /v1/vms/{id}`) and update `info`. */
  async refresh(): Promise<SandboxInfo> {
    this.info = sandboxInfoFromRecord(await this.client.json<Json>("GET", `/v1/vms/${enc(this.id)}`));
    return this.info;
  }

  /** `DELETE /v1/vms/{id}` (204). Sandboxes are VM records, so the generic VM delete removes one. */
  async delete(): Promise<void> {
    await this.client.json("DELETE", `/v1/vms/${enc(this.id)}`, undefined, { expect: [204] });
  }

  /**
   * Run a command in the guest (`POST /process`). A string runs with `/bin/sh -c`; an array is
   * shell-quoted and joined. `timeoutSeconds` is the guest-side limit (server default 30); a
   * command that exceeds it returns a non-zero exit code instead of throwing.
   */
  async run(command: string | string[], opts: { timeoutSeconds?: number } = {}): Promise<ExecResult> {
    const cmd = typeof command === "string" ? command : command.map(shellQuote).join(" ");
    const payload: Json = { command: cmd };
    if (opts.timeoutSeconds !== undefined) payload.timeout_seconds = Math.trunc(opts.timeoutSeconds);
    const limit = opts.timeoutSeconds !== undefined ? Math.trunc(opts.timeoutSeconds) : DEFAULT_EXEC_TIMEOUT_SECS;
    const data = await this.client.json<Json>("POST", this.path("/process"), payload, {
      timeoutMs: limit * 1000 + EXEC_HTTP_SLACK_MS,
    });
    if (!data || data.result !== "exec") throw new ApiError(200, data, "unexpected process response");
    const exitCode = Number(data.exit_code);
    return { exitCode, stdout: String(data.stdout ?? ""), stderr: String(data.stderr ?? ""), ok: exitCode === 0 };
  }

  /** `POST /fs/read`: file bytes and mode. */
  async readFileInfo(path: string): Promise<FileContent> {
    const data = await this.client.json<Json>("POST", this.path("/fs/read"), { path });
    if (!data || data.result !== "file-content") throw new ApiError(200, data, "unexpected fs/read response");
    return { data: new Uint8Array(Buffer.from(String(data.content_base64), "base64")), mode: Number(data.mode ?? 0) };
  }

  async readFile(path: string): Promise<Uint8Array> {
    return (await this.readFileInfo(path)).data;
  }

  async readText(path: string): Promise<string> {
    return new TextDecoder().decode(await this.readFile(path));
  }

  /**
   * `POST /fs/write`. A string is encoded as UTF-8. `mode` are Unix permission bits (server
   * default 0o644). Parent directories are created by the guest agent.
   */
  async writeFile(path: string, data: Uint8Array | string, mode?: number): Promise<void> {
    const raw = typeof data === "string" ? new TextEncoder().encode(data) : data;
    if (raw.length > MAX_FILE_TRANSFER_BYTES) {
      throw new RangeError(`file is ${raw.length} bytes; the guest agent limit is ${MAX_FILE_TRANSFER_BYTES}`);
    }
    const payload: Json = { path, content_base64: toB64(raw) };
    if (mode !== undefined) payload.mode = Math.trunc(mode);
    const out = await this.client.json<Json>("POST", this.path("/fs/write"), payload);
    if (!out || out.result !== "file-written") throw new ApiError(200, out, "unexpected fs/write response");
  }

  /** `POST /snapshot`. `path` is on the **server** host. Returns the path the server reports. */
  async snapshot(path: string): Promise<string> {
    const data = await this.client.json<Json>("POST", this.path("/snapshot"), { path });
    return String(data.path ?? path);
  }

  /** `POST /baseline`: record the regular files under `paths` so {@link changes} can diff. Needs the guest agent. */
  async baseline(paths: string[]): Promise<BaselineSummary> {
    const d = await this.client.json<Json>("POST", this.path("/baseline"), { paths });
    return { files: Number(d.files ?? 0), mode: String(d.mode ?? ""), paths: (d.paths as string[]) ?? [] };
  }

  /** `POST /changes`: files added, modified or deleted since the last baseline. Throws {@link NotFound} without one. */
  async changes(paths?: string[]): Promise<ChangeSet> {
    const d = await this.client.json<Json>("POST", this.path("/changes"), paths === undefined ? {} : { paths });
    const added = (d.added as string[]) ?? [];
    const modified = (d.modified as string[]) ?? [];
    const deleted = (d.deleted as string[]) ?? [];
    return {
      added,
      modified,
      deleted,
      unchanged: Number(d.unchanged ?? 0),
      mode: String(d.mode ?? ""),
      paths: (d.paths as string[]) ?? [],
      baselineTakenAtUnix: Number(d.baseline_taken_at_unix ?? 0),
      clean: added.length + modified.length + deleted.length === 0,
    };
  }

  /**
   * `POST /dry-run`: run `command`, return the exec result plus `changes`, then discard everything.
   * `paths` is required on native flux-vm sandboxes; other VM backends answer 501.
   */
  dryRun(command: string, opts: { timeoutSeconds?: number; paths?: string[] } = {}): Promise<Json> {
    const body: Json = { command };
    if (opts.timeoutSeconds !== undefined) body.timeout_seconds = opts.timeoutSeconds;
    if (opts.paths !== undefined) body.paths = opts.paths;
    return this.client.json("POST", this.path("/dry-run"), body);
  }

  /**
   * Call an HTTP service inside the guest through the API's reverse proxy. `port` selects
   * `/v1/sandboxes/{id}/http/{port}/{path}`; `null` uses `/sandbox/{id}/{path}`. The guest's own
   * status codes are returned, not thrown.
   */
  async http(
    port: number | null,
    method: string,
    path: string,
    opts: {
      body?: Uint8Array | string | Json | unknown[];
      headers?: Record<string, string>;
      params?: Record<string, string | number | boolean | Array<string | number | boolean>>;
      timeoutMs?: number;
    } = {},
  ): Promise<HttpResponse> {
    const rel = encodeProxyPath(path);
    const sid = enc(this.id);
    let url = port === null ? `/sandbox/${sid}/${rel}` : `/v1/sandboxes/${sid}/http/${Math.trunc(port)}/${rel}`;
    if (opts.params) {
      const q = new URLSearchParams();
      for (const [k, v] of Object.entries(opts.params)) {
        for (const item of Array.isArray(v) ? v : [v]) q.append(k, String(item));
      }
      const qs = q.toString();
      if (qs) url += `?${qs}`;
    }
    const headers: Record<string, string> = { ...(opts.headers ?? {}) };
    const hasType = Object.keys(headers).some((k) => k.toLowerCase() === "content-type");
    let raw: Uint8Array | string | undefined;
    const b = opts.body;
    if (b === undefined || b === null) raw = undefined;
    else if (b instanceof Uint8Array) {
      raw = b;
      if (!hasType) headers["Content-Type"] = "application/octet-stream";
    } else if (typeof b === "string") {
      raw = b;
      if (!hasType) headers["Content-Type"] = "text/plain; charset=utf-8";
    } else {
      raw = JSON.stringify(b);
      if (!hasType) headers["Content-Type"] = "application/json";
    }
    const r = await this.client.send(method.toUpperCase(), url, raw, headers, opts.timeoutMs);
    const text = () => new TextDecoder().decode(r.body);
    const ok = r.status >= 200 && r.status < 300;
    return {
      status: r.status,
      headers: r.headers,
      body: r.body,
      ok,
      text,
      json: <T>() => JSON.parse(text()) as T,
      raiseForStatus: () => {
        if (!ok) throw new ApiError(r.status, text());
      },
    };
  }
}
