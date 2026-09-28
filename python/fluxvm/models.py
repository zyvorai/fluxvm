# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
"""Plain data types returned by the client."""

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class SandboxInfo:
    """The subset of the server's ``VmRecord`` that is useful to callers.

    ``raw`` keeps the complete record so fields not modelled here stay
    reachable. ``confidential`` is only present on create responses when a
    confidential mode was requested.
    """

    id: str
    name: str
    status: str
    backend: Optional[str] = None
    guest_ip: Optional[str] = None
    pid: Optional[int] = None
    created_at: Optional[str] = None
    expires_at: Optional[str] = None
    confidential: Optional[Dict[str, Any]] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_record(cls, rec: Dict[str, Any]) -> "SandboxInfo":
        return cls(
            id=str(rec["id"]),
            name=rec.get("name", ""),
            status=rec.get("status", ""),
            backend=rec.get("backend"),
            guest_ip=rec.get("guest_ip"),
            pid=rec.get("pid"),
            created_at=rec.get("created_at"),
            expires_at=rec.get("expires_at"),
            confidential=rec.get("confidential"),
            raw=rec,
        )


@dataclass
class ExecResult:
    """Outcome of a command run through the guest agent."""

    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


@dataclass
class FileContent:
    """A guest file: raw bytes plus the Unix mode bits the guest reported."""

    data: bytes
    mode: int


@dataclass
class HttpResponse:
    """A response proxied from an HTTP service inside the guest.

    The proxy relays the guest's own status codes, so a 4xx/5xx here is not
    raised as an error; call :meth:`raise_for_status` if you want that.
    """

    status: int
    headers: Dict[str, str]
    body: bytes

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def text(self, encoding: str = "utf-8") -> str:
        return self.body.decode(encoding, errors="replace")

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))

    def raise_for_status(self) -> None:
        if not self.ok:
            from .errors import ApiError

            raise ApiError(self.status, self.text())


@dataclass
class Volume:
    """A named persistent volume to attach (needs a QEMU-backed template)."""

    name: str
    guest_path: str
    read_only: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "guest_path": self.guest_path,
                "read_only": self.read_only}
