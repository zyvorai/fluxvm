// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { after, before, describe, it } from "node:test";
import {
  ApiError,
  AuthError,
  ConnectionFailed,
  ForbiddenError,
  FluxVM,
  NotFound,
  RateLimited,
  RequestTimeout,
  shellQuote,
} from "../src/index.js";

interface Seen {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

let server: http.Server;
let base: string;
let seen: Seen[] = [];
/** Set per test: how the mock answers the next request. */
let respond: (req: Seen, res: http.ServerResponse) => void = (_r, res) => res.end("{}");

before(async () => {
  server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const s: Seen = { method: req.method!, url: req.url!, headers: req.headers, body: Buffer.concat(chunks).toString() };
      seen.push(s);
      respond(s, res);
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(() => {
  server.closeAllConnections();
  server.close();
});

function reply(status: number, body: unknown, headers: Record<string, string> = {}) {
  return (_r: Seen, res: http.ServerResponse) => {
    res.writeHead(status, { "content-type": "application/json", ...headers });
    res.end(typeof body === "string" ? body : JSON.stringify(body));
  };
}

const rec = { id: "sb-1", name: "demo", status: "running", backend: "flux-vm", guest_ip: "10.0.0.2" };
const client = () => new FluxVM({ baseUrl: base + "/", token: "tok" });
const last = () => seen[seen.length - 1];

describe("FluxVM client", () => {
  it("sends the bearer token and creates a sandbox with only the fields that were set", async () => {
    seen = [];
    respond = reply(201, rec);
    const sb = await client().createSandbox({ name: "demo", ttlSeconds: 60, memoryMib: 512, volumes: [{ name: "v", guestPath: "/data" }] });
    assert.equal(sb.id, "sb-1");
    assert.equal(sb.info.guestIp, "10.0.0.2");
    assert.equal(last().method, "POST");
    assert.equal(last().url, "/v1/sandboxes");
    assert.equal(last().headers.authorization, "Bearer tok");
    assert.deepEqual(JSON.parse(last().body), {
      name: "demo",
      ttl_seconds: 60,
      memory_mib: 512,
      volumes: [{ name: "v", guest_path: "/data", read_only: false }],
    });
  });

  it("sends gpus and rejects a bad count before sending anything", async () => {
    seen = [];
    respond = reply(201, rec);
    await client().createSandbox({ gpus: 2 });
    assert.equal(JSON.parse(last().body).gpus, 2);
    await client().createSandbox({});
    assert.equal("gpus" in JSON.parse(last().body), false);
    seen = [];
    for (const bad of [-1, 9, 1.5]) {
      await assert.rejects(() => client().createSandbox({ gpus: bad }), RangeError);
    }
    assert.equal(seen.length, 0);
  });

  it("rejects a bad confidential mode before sending anything", async () => {
    seen = [];
    await assert.rejects(() => client().createSandbox({ confidential: "maybe" as never }), /confidential/);
    assert.equal(seen.length, 0);
  });

  it("lists and attaches", async () => {
    respond = reply(200, { items: [rec] });
    assert.equal((await client().listSandboxes())[0].name, "demo");
    respond = reply(200, rec);
    const sb = await client().getSandbox("a/b");
    assert.equal(last().url, "/v1/vms/a%2Fb");
    assert.equal(sb.info.status, "running");
  });

  it("maps statuses to error classes", async () => {
    const cases: Array<[number, unknown, new (...a: never[]) => Error]> = [
      [401, { error: "no" }, AuthError],
      [403, { error: "admin only" }, ForbiddenError],
      [404, { error: "gone" }, NotFound],
      [400, { error: "VM not found" }, NotFound],
      [500, "boom", ApiError],
    ];
    for (const [status, body, cls] of cases) {
      respond = reply(status, body);
      await assert.rejects(() => client().listSandboxes(), (e: unknown) => {
        assert.ok(e instanceof cls, `${status} should be ${cls.name}, got ${(e as Error).name}`);
        assert.equal((e as ApiError).status, status);
        return true;
      });
    }
    respond = reply(403, { error: "admin only" });
    await assert.rejects(() => client().listSandboxes(), /admin only/);
    // A 403 is also an AuthError, as in the Python client.
    await assert.rejects(() => client().listSandboxes(), AuthError);
  });

  it("reads Retry-After on 429", async () => {
    respond = reply(429, { error: "slow down" }, { "retry-after": "7" });
    await assert.rejects(() => client().listSandboxes(), (e: unknown) => e instanceof RateLimited && e.retryAfter === 7);
    respond = reply(429, { error: "x" }, { "retry-after": "soon" });
    await assert.rejects(() => client().listSandboxes(), (e: unknown) => e instanceof RateLimited && e.retryAfter === undefined);
  });

  it("reports an unreachable server and a slow one", async () => {
    await assert.rejects(() => new FluxVM({ baseUrl: "http://127.0.0.1:1" }).health(), ConnectionFailed);
    respond = () => {
      /* never answers */
    };
    await assert.rejects(() => new FluxVM({ baseUrl: base, timeoutMs: 50 }).health(), RequestTimeout);
    respond = reply(200, {});
  });

  it("does not follow redirects", async () => {
    respond = reply(302, "", { location: "/elsewhere" });
    const sb = await new FluxVM({ baseUrl: base }).createSandbox().catch((e) => e);
    assert.ok(sb instanceof ApiError && sb.status === 302);
  });

  it("run: quotes an argv array and passes the guest-side timeout", async () => {
    respond = reply(201, rec);
    const sb = await client().createSandbox();
    respond = reply(200, { result: "exec", exit_code: 3, stdout: "out", stderr: "err" });
    const r = await sb.run(["echo", "it's a test", "$HOME"], { timeoutSeconds: 5 });
    assert.deepEqual(r, { exitCode: 3, stdout: "out", stderr: "err", ok: false });
    assert.equal(last().url, "/v1/sandboxes/sb-1/process");
    assert.deepEqual(JSON.parse(last().body), { command: `echo 'it'"'"'s a test' '$HOME'`, timeout_seconds: 5 });
    respond = reply(200, { result: "nope" });
    await assert.rejects(() => sb.run("true"), /unexpected process response/);
  });

  it("shellQuote matches shlex.quote", () => {
    assert.equal(shellQuote(""), "''");
    assert.equal(shellQuote("plain-1.2/x"), "plain-1.2/x");
    assert.equal(shellQuote("a b"), "'a b'");
    assert.equal(shellQuote("$(rm)"), "'$(rm)'");
  });

  it("files: base64 both ways, mode, and the size limit", async () => {
    respond = reply(201, rec);
    const sb = await client().createSandbox();
    respond = reply(200, { result: "file-written" });
    await sb.writeFile("/tmp/a.txt", "héllo", 0o600);
    const sent = JSON.parse(last().body);
    assert.equal(sent.path, "/tmp/a.txt");
    assert.equal(sent.mode, 0o600);
    assert.equal(Buffer.from(sent.content_base64, "base64").toString(), "héllo");

    respond = reply(200, { result: "file-content", content_base64: Buffer.from("hi").toString("base64"), mode: 420 });
    assert.equal(await sb.readText("/tmp/a.txt"), "hi");
    assert.equal((await sb.readFileInfo("/tmp/a.txt")).mode, 420);

    seen = [];
    await assert.rejects(() => sb.writeFile("/big", new Uint8Array(64 * 1024 * 1024 + 1)), RangeError);
    assert.equal(seen.length, 0);
  });

  it("baseline, changes and dry-run", async () => {
    respond = reply(201, rec);
    const sb = await client().createSandbox();
    respond = reply(200, { files: 4, mode: "sha256", paths: ["/w"] });
    assert.deepEqual(await sb.baseline(["/w"]), { files: 4, mode: "sha256", paths: ["/w"] });
    respond = reply(200, { added: [], modified: [], deleted: [], unchanged: 4, mode: "sha256", paths: ["/w"], baseline_taken_at_unix: 9 });
    const clean = await sb.changes();
    assert.equal(clean.clean, true);
    assert.deepEqual(JSON.parse(last().body), {});
    respond = reply(200, { added: ["/w/x"], modified: [], deleted: [], unchanged: 3, mode: "sha256", paths: ["/w"], baseline_taken_at_unix: 9 });
    assert.equal((await sb.changes(["/w"])).clean, false);
    assert.deepEqual(JSON.parse(last().body), { paths: ["/w"] });
    respond = reply(404, { error: "no baseline" });
    await assert.rejects(() => sb.changes(), NotFound);
    respond = reply(200, { discarded: true, reverted_via: "snapshot" });
    const d = await sb.dryRun("make", { timeoutSeconds: 9, paths: ["/w"] });
    assert.equal(d.reverted_via, "snapshot");
    assert.deepEqual(JSON.parse(last().body), { command: "make", timeout_seconds: 9, paths: ["/w"] });
  });

  it("http proxy: routes, path encoding, params, body types, guest status codes", async () => {
    respond = reply(201, rec);
    const sb = await client().createSandbox();
    respond = (_r, res) => {
      res.writeHead(418, { "content-type": "application/json" });
      res.end('{"tea":true}');
    };
    const r = await sb.http(8080, "get", "/a b/ü;x=1", { params: { q: ["1", "2"], flag: true } });
    assert.equal(last().method, "GET");
    assert.equal(last().url, "/v1/sandboxes/sb-1/http/8080/a%20b/%C3%BC;x=1?q=1&q=2&flag=true");
    assert.equal(r.status, 418);
    assert.equal(r.ok, false);
    assert.deepEqual(r.json(), { tea: true });
    assert.throws(() => r.raiseForStatus(), ApiError);

    await sb.http(null, "POST", "hook", { body: { a: 1 } });
    assert.equal(last().url, "/sandbox/sb-1/hook");
    assert.equal(last().headers["content-type"], "application/json");
    await sb.http(1, "PUT", "x", { body: "text" });
    assert.match(String(last().headers["content-type"]), /^text\/plain/);
    await sb.http(1, "PUT", "x", { body: new Uint8Array([1, 2]) });
    assert.equal(last().headers["content-type"], "application/octet-stream");
    await sb.http(1, "PUT", "x", { body: "{}", headers: { "content-type": "application/x-custom" } });
    assert.equal(last().headers["content-type"], "application/x-custom");
  });

  it("withSandbox deletes afterwards, even when the callback throws, and tolerates 404", async () => {
    seen = [];
    respond = (req, res) => (req.method === "DELETE" ? (res.writeHead(204), res.end()) : reply(201, rec)(req, res));
    await assert.rejects(() => client().withSandbox({}, async () => { throw new Error("boom"); }), /boom/);
    assert.equal(last().method, "DELETE");
    assert.equal(last().url, "/v1/vms/sb-1");

    respond = (req, res) => (req.method === "DELETE" ? reply(404, { error: "gone" })(req, res) : reply(201, rec)(req, res));
    assert.equal(await client().withSandbox({}, async (sb) => sb.id), "sb-1");
  });

  it("health and openapi need no body", async () => {
    respond = reply(200, { ok: true });
    assert.equal(await client().health(), true);
    respond = reply(200, { openapi: "3.0.0" });
    assert.equal((await client().openapi()).openapi, "3.0.0");
  });
});
