# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
"""HTTP client for the FluxVM agent-sandbox API (standard library only)."""

import base64
import json
import shlex
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from .errors import (
    ApiError,
    AuthError,
    ConnectionFailed,
    FluxVMError,
    ForbiddenError,
    NotFound,
    RateLimited,
    RequestTimeout,
)
from .models import BaselineSummary, ChangeSet, ExecResult, FileContent, HttpResponse, SandboxInfo, Volume

# Mirrors fluxvm_guest_protocol::MAX_FILE_TRANSFER_BYTES: the guest agent
# moves a whole file as one base64 JSON line and refuses anything larger.
MAX_FILE_TRANSFER_BYTES = 64 * 1024 * 1024
# Mirrors fluxvm_guest_protocol::DEFAULT_EXEC_TIMEOUT_SECS.
DEFAULT_EXEC_TIMEOUT_SECS = 30
# The server waits ``timeout_seconds + 5`` for the guest agent; give the HTTP
# call a little more so a guest-side timeout is reported by the server rather
# than as a client-side socket timeout.
_EXEC_HTTP_SLACK_SECS = 10

_PATH_SAFE = "/:@!$&'()*+,;=-._~"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: proxied guest 3xx responses must pass through."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def _is_timeout(exc: BaseException) -> bool:
    if isinstance(exc, socket.timeout):
        return True
    if isinstance(exc, urllib.error.URLError):
        return _is_timeout(exc.reason) if isinstance(exc.reason, BaseException) else False
    return False


def _error_from_response(status: int, raw: bytes, headers: Mapping[str, str]) -> ApiError:
    text = raw.decode("utf-8", errors="replace")
    body: Any = text
    message = text
    try:
        parsed = json.loads(text)
        body = parsed
        if isinstance(parsed, dict) and "error" in parsed:
            message = str(parsed["error"])
    except ValueError:
        pass
    if status == 401:
        return AuthError(status, body, message)
    if status == 403:
        return ForbiddenError(status, body, message)
    if status == 404:
        return NotFound(status, body, message)
    # GET/DELETE /v1/vms/{id} answer an unknown VM with 400 "VM not found"
    # (the server maps most handler errors to 400), not 404.
    if status == 400 and message.strip().lower() == "vm not found":
        return NotFound(status, body, message)
    if status == 429:
        retry_after = None
        value = headers.get("Retry-After")
        if value is not None:
            try:
                retry_after = float(value)
            except ValueError:
                retry_after = None
        return RateLimited(status, body, message, retry_after)
    return ApiError(status, body, message)


class FluxVM:
    """Client for one FluxVM API endpoint.

    :param base_url: e.g. ``"http://127.0.0.1:8080"``.
    :param token: bearer token (static token or OIDC JWT). Omit only when the
        server runs unauthenticated on loopback.
    :param timeout: default per-request socket timeout in seconds.
    :param headers: extra headers sent on every request (for example the
        ``X-Client-Cert-*`` identity headers set by a trusted mTLS frontend).
    :param ssl_context: custom :class:`ssl.SSLContext` for ``https`` URLs.
    """

    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        timeout: float = 30.0,
        headers: Optional[Mapping[str, str]] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
    ):
        if not base_url:
            raise ValueError("base_url is required")
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.headers = dict(headers or {})
        handlers: List[Any] = [_NoRedirect()]
        if ssl_context is not None:
            handlers.append(urllib.request.HTTPSHandler(context=ssl_context))
        self._opener = urllib.request.build_opener(*handlers)

    # ------------------------------------------------------------------ core

    def _send(
        self,
        method: str,
        path: str,
        body: Optional[bytes] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Tuple[int, Dict[str, str], bytes]:
        """One request; returns (status, headers, body) for every HTTP status."""
        url = self.base_url + path
        req = urllib.request.Request(url, data=body, method=method)
        merged = dict(self.headers)
        if headers:
            merged.update(headers)
        if self.token:
            merged["Authorization"] = "Bearer " + self.token
        for key, value in merged.items():
            req.add_header(key, value)
        try:
            with self._opener.open(req, timeout=self.timeout if timeout is None else timeout) as resp:
                return resp.status, dict(resp.headers.items()), resp.read()
        except urllib.error.HTTPError as err:
            try:
                return err.code, dict(err.headers.items()), err.read()
            finally:
                err.close()
        except (urllib.error.URLError, OSError) as err:
            if _is_timeout(err):
                raise RequestTimeout("{} {} timed out".format(method, path)) from err
            raise ConnectionFailed("{} {}: {}".format(method, url, err)) from err

    def _json(
        self,
        method: str,
        path: str,
        payload: Optional[Mapping[str, Any]] = None,
        timeout: Optional[float] = None,
        expect: Sequence[int] = (200, 201),
    ) -> Any:
        body = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        status, resp_headers, raw = self._send(method, path, body, headers, timeout)
        if status not in expect:
            raise _error_from_response(status, raw, resp_headers)
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError as err:
            raise ApiError(status, raw.decode("utf-8", errors="replace"),
                           "response was not JSON") from err

    # ------------------------------------------------------------- public API

    def health(self) -> bool:
        """``GET /healthz`` (no auth needed). True when the server says ok."""
        return bool(self._json("GET", "/healthz").get("ok"))

    def openapi(self) -> Dict[str, Any]:
        """``GET /v1/openapi.json`` (no auth needed)."""
        return self._json("GET", "/v1/openapi.json")

    def host_confidential(self) -> Dict[str, Any]:
        """``GET /v1/host/confidential``: what the host offers for confidential guests."""
        return self._json("GET", "/v1/host/confidential")

    def create_sandbox(
        self,
        name: Optional[str] = None,
        template: Optional[str] = None,
        spec: Optional[Mapping[str, Any]] = None,
        ttl_seconds: Optional[int] = None,
        http_proxy_port: Optional[int] = None,
        http_proxy_ports: Optional[Sequence[int]] = None,
        volumes: Optional[Sequence[Union[Volume, Mapping[str, Any]]]] = None,
        vcpus: Optional[int] = None,
        memory_mib: Optional[int] = None,
        confidential: Optional[str] = None,
        procbox: Optional[Mapping[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> "Sandbox":
        """``POST /v1/sandboxes``. Fields left as ``None`` are omitted so the
        server's defaults apply. ``template`` names a template under the
        server's templates dir; ``spec`` is a raw create spec (as accepted by
        ``POST /v1/vms``). ``confidential`` is ``"auto"`` or ``"required"``. ``procbox`` (``{}`` for
        defaults, or limits such as ``{"timeout_seconds": 60, "max_memory_mib": 512}``)
        selects a rootless process sandbox instead of a VM; the server must have
        ``[sandbox.procbox] enabled = true``.
        """
        if confidential is not None and confidential not in ("auto", "required"):
            raise ValueError('confidential must be "auto" or "required"')
        payload: Dict[str, Any] = {}
        for key, value in (
            ("name", name),
            ("template", template),
            ("spec", dict(spec) if spec is not None else None),
            ("ttl_seconds", ttl_seconds),
            ("http_proxy_port", http_proxy_port),
            ("http_proxy_ports", list(http_proxy_ports) if http_proxy_ports else None),
            ("volumes", [v.to_dict() if isinstance(v, Volume) else dict(v) for v in volumes]
             if volumes else None),
            ("vcpus", vcpus),
            ("memory_mib", memory_mib),
            ("confidential", confidential),
            ("procbox", dict(procbox) if procbox is not None else None),
        ):
            if value is not None:
                payload[key] = value
        record = self._json("POST", "/v1/sandboxes", payload, timeout=timeout, expect=(201,))
        return Sandbox(self, SandboxInfo.from_record(record))

    def list_sandboxes(self) -> List[SandboxInfo]:
        """``GET /v1/sandboxes``: the caller's tenant's sandboxes."""
        data = self._json("GET", "/v1/sandboxes")
        return [SandboxInfo.from_record(item) for item in data.get("items", [])]

    def get_sandbox(self, sandbox_id: str) -> "Sandbox":
        """Attach to an existing sandbox via ``GET /v1/vms/{id}`` (a sandbox
        is a VM record; there is no dedicated ``GET /v1/sandboxes/{id}``)."""
        record = self._json("GET", "/v1/vms/" + urllib.parse.quote(sandbox_id, safe=""))
        return Sandbox(self, SandboxInfo.from_record(record))


class Sandbox:
    """A handle to one sandbox. Use as a context manager to delete on exit."""

    def __init__(self, client: FluxVM, info: SandboxInfo):
        self._client = client
        self.info = info

    @property
    def id(self) -> str:
        return self.info.id

    def __repr__(self) -> str:
        return "Sandbox(id={!r}, name={!r}, status={!r})".format(
            self.info.id, self.info.name, self.info.status)

    def __enter__(self) -> "Sandbox":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        try:
            self.delete()
        except NotFound:
            pass

    def _path(self, suffix: str) -> str:
        return "/v1/sandboxes/{}{}".format(urllib.parse.quote(self.id, safe=""), suffix)

    def refresh(self) -> SandboxInfo:
        """Re-read the record (``GET /v1/vms/{id}``) and update ``self.info``."""
        record = self._client._json(
            "GET", "/v1/vms/" + urllib.parse.quote(self.id, safe=""))
        self.info = SandboxInfo.from_record(record)
        return self.info

    def delete(self) -> None:
        """``DELETE /v1/vms/{id}`` (204). Sandboxes are VM records, so the
        generic VM delete is what removes one."""
        self._client._json("DELETE", "/v1/vms/" + urllib.parse.quote(self.id, safe=""),
                           expect=(204,))

    def run(
        self,
        command: Union[str, Sequence[str]],
        timeout: Optional[int] = None,
    ) -> ExecResult:
        """Run a command in the guest (``POST /process``).

        ``command`` is a shell string (the guest agent runs it with
        ``/bin/sh -c``); a list is joined with :func:`shlex.join`.
        ``timeout`` is the guest-side limit in whole seconds (server default
        30); a command that exceeds it comes back with a non-zero exit code
        rather than raising.
        """
        if not isinstance(command, str):
            command = shlex.join(list(command))
        payload: Dict[str, Any] = {"command": command}
        if timeout is not None:
            payload["timeout_seconds"] = int(timeout)
        limit = int(timeout) if timeout is not None else DEFAULT_EXEC_TIMEOUT_SECS
        data = self._client._json(
            "POST", self._path("/process"), payload,
            timeout=limit + _EXEC_HTTP_SLACK_SECS)
        if not isinstance(data, dict) or data.get("result") != "exec":
            raise ApiError(200, data, "unexpected process response")
        return ExecResult(int(data["exit_code"]), data.get("stdout", ""), data.get("stderr", ""))

    def read_file_info(self, path: str) -> FileContent:
        """``POST /fs/read``: file bytes and mode."""
        data = self._client._json("POST", self._path("/fs/read"), {"path": path})
        if not isinstance(data, dict) or data.get("result") != "file-content":
            raise ApiError(200, data, "unexpected fs/read response")
        return FileContent(base64.b64decode(data["content_base64"]), int(data.get("mode", 0)))

    def read_file(self, path: str) -> bytes:
        return self.read_file_info(path).data

    def read_text(self, path: str, encoding: str = "utf-8") -> str:
        return self.read_file(path).decode(encoding)

    def write_file(self, path: str, data: Union[bytes, str], mode: Optional[int] = None) -> None:
        """``POST /fs/write``. ``str`` is encoded as UTF-8. ``mode`` are Unix
        permission bits (server default 0o644). Parent directories are created
        by the guest agent."""
        raw = data.encode("utf-8") if isinstance(data, str) else bytes(data)
        if len(raw) > MAX_FILE_TRANSFER_BYTES:
            raise ValueError(
                "file is {} bytes; the guest agent limit is {}".format(
                    len(raw), MAX_FILE_TRANSFER_BYTES))
        payload: Dict[str, Any] = {
            "path": path,
            "content_base64": base64.b64encode(raw).decode("ascii"),
        }
        if mode is not None:
            payload["mode"] = int(mode)
        data_out = self._client._json("POST", self._path("/fs/write"), payload)
        if not isinstance(data_out, dict) or data_out.get("result") != "file-written":
            raise ApiError(200, data_out, "unexpected fs/write response")

    def snapshot(self, path: str) -> str:
        """``POST /snapshot``. ``path`` is a path on the **server** host where
        the snapshot is written. Returns the path the server reports."""
        data = self._client._json("POST", self._path("/snapshot"), {"path": path})
        return str(data.get("path", path))

    def baseline(self, paths: Sequence[str]) -> BaselineSummary:
        """``POST /baseline``: record the regular files under ``paths``
        (absolute guest directories) so :meth:`changes` can diff against them.
        Replaces any earlier baseline. Needs the guest agent."""
        data = self._client._json("POST", self._path("/baseline"), {"paths": list(paths)})
        return BaselineSummary(
            files=int(data.get("files", 0)),
            mode=str(data.get("mode", "")),
            paths=list(data.get("paths", [])),
        )

    def changes(self, paths: Optional[Sequence[str]] = None) -> ChangeSet:
        """``POST /changes``: files added, modified or deleted since the last
        :meth:`baseline`. ``paths`` narrows the diff to a subset of the
        baseline directories. Raises :class:`NotFound` if no baseline exists.
        Reports changes only; use snapshot/restore to roll back."""
        body = {} if paths is None else {"paths": list(paths)}
        data = self._client._json("POST", self._path("/changes"), body)
        return ChangeSet(
            added=list(data.get("added", [])),
            modified=list(data.get("modified", [])),
            deleted=list(data.get("deleted", [])),
            unchanged=int(data.get("unchanged", 0)),
            mode=str(data.get("mode", "")),
            paths=list(data.get("paths", [])),
            baseline_taken_at_unix=int(data.get("baseline_taken_at_unix", 0)),
        )

    def dry_run(
        self,
        command: str,
        timeout: Optional[int] = None,
        paths: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        """``POST /dry-run``: run ``command`` and return the exec result plus
        ``changes`` (added/modified/deleted), then discard everything.
        Procbox sandboxes run on a throwaway copy of the workspace
        (``reverted_via: "workspace-copy"``). Native flux-vm sandboxes are
        snapshotted and restored (``reverted_via: "snapshot"``, memory and
        disk both revert); ``paths`` is required there and the restore takes
        seconds. Other VM backends answer 501."""
        body: Dict[str, Any] = {"command": command}
        if timeout is not None:
            body["timeout_seconds"] = timeout
        if paths is not None:
            body["paths"] = list(paths)
        return self._client._json("POST", self._path("/dry-run"), body)

    def http(
        self,
        port: Optional[int],
        method: str,
        path: str,
        body: Optional[Union[bytes, str, Mapping[str, Any], Sequence[Any]]] = None,
        headers: Optional[Mapping[str, str]] = None,
        params: Optional[Mapping[str, Any]] = None,
        timeout: Optional[float] = None,
    ) -> HttpResponse:
        """Call an HTTP service inside the guest through the API's reverse proxy.

        ``port`` selects ``/v1/sandboxes/{id}/http/{port}/{path}``; ``None``
        uses the default-port route ``/sandbox/{id}/{path}``. ``body`` may be
        bytes, str, or a dict/list (sent as JSON). The guest's own status
        codes are returned, not raised; authentication failures on the API
        itself (401/403) are indistinguishable from a guest 401/403 here.
        The sandbox needs a routable guest IP (``network.mode=tap`` with a
        netns); otherwise the server answers 400/502.
        """
        method = method.upper()
        rel = urllib.parse.quote(path.lstrip("/"), safe=_PATH_SAFE)
        sid = urllib.parse.quote(self.id, safe="")
        if port is None:
            url = "/sandbox/{}/{}".format(sid, rel)
        else:
            url = "/v1/sandboxes/{}/http/{}/{}".format(sid, int(port), rel)
        if params:
            url += "?" + urllib.parse.urlencode(params, doseq=True)
        send_headers = dict(headers or {})
        if any(k.lower() == "content-type" for k in send_headers):
            send_headers = {("Content-Type" if k.lower() == "content-type" else k): v
                            for k, v in send_headers.items()}
        raw: Optional[bytes]
        if body is None:
            raw = None
        elif isinstance(body, bytes):
            raw = body
            # urllib would otherwise label any body form-urlencoded.
            send_headers.setdefault("Content-Type", "application/octet-stream")
        elif isinstance(body, str):
            raw = body.encode("utf-8")
            send_headers.setdefault("Content-Type", "text/plain; charset=utf-8")
        else:
            raw = json.dumps(body).encode("utf-8")
            send_headers.setdefault("Content-Type", "application/json")
        status, resp_headers, content = self._client._send(
            method, url, raw, send_headers, timeout)
        return HttpResponse(status, resp_headers, content)
