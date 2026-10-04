//! `GET /v1/openapi.json`: OpenAPI 3.1 description of the VM lifecycle routes.

use serde_json::{Map, Value, json};

struct Op {
    method: &'static str,
    path: &'static str,
    summary: &'static str,
    tag: &'static str,
    body: Option<&'static str>,
    response: Option<&'static str>,
    status: &'static str,
    query: &'static [(&'static str, &'static str)],
}

const fn op(
    method: &'static str,
    path: &'static str,
    summary: &'static str,
    tag: &'static str,
) -> Op {
    Op {
        method,
        path,
        summary,
        tag,
        body: None,
        response: None,
        status: "200",
        query: &[],
    }
}

impl Op {
    const fn body(mut self, schema: &'static str) -> Self {
        self.body = Some(schema);
        self
    }
    const fn returns(mut self, schema: &'static str) -> Self {
        self.response = Some(schema);
        self
    }
    const fn status(mut self, status: &'static str) -> Self {
        self.status = status;
        self
    }
    const fn query(mut self, q: &'static [(&'static str, &'static str)]) -> Self {
        self.query = q;
        self
    }
}

const VMS: &str = "vms";
const DISKS: &str = "disks";
const SNAPSHOTS: &str = "snapshots";
const EVENTS: &str = "events";
const TEMPLATES: &str = "vm-templates";
const HOST: &str = "host";

fn ops() -> Vec<Op> {
    vec![
        op("get", "/healthz", "Liveness probe (no auth)", HOST),
        op("get", "/readyz", "Readiness probe (no auth)", HOST),
        op(
            "get",
            "/v1/quotas/me",
            "Caller token's quota limits and usage",
            HOST,
        ),
        op("get", "/v1/vms", "List VMs", VMS)
            .returns("VmList")
            .query(&[
                ("name", "Exact VM name"),
                ("tenant", "Tenant id"),
                ("label", "Label selector, e.g. env=prod,!tmp"),
            ]),
        op("post", "/v1/vms", "Create a VM", VMS)
            .body("CreateVmRequest")
            .returns("VmRecord")
            .status("201"),
        op("get", "/v1/vms/{id}", "Get a VM", VMS).returns("VmRecord"),
        op(
            "patch",
            "/v1/vms/{id}",
            "Rename and/or edit labels (null value removes)",
            VMS,
        )
        .body("VmPatch")
        .returns("VmRecord"),
        op("delete", "/v1/vms/{id}", "Delete a VM", VMS).status("204"),
        op("post", "/v1/vms/{id}/start", "Start a VM", VMS).returns("VmRecord"),
        op("post", "/v1/vms/{id}/stop", "Stop a VM", VMS).returns("VmRecord"),
        op("post", "/v1/vms/{id}/restart", "Stop then start a VM", VMS).returns("VmRecord"),
        op("post", "/v1/vms/{id}/pause", "Pause vCPUs", VMS).returns("VmRecord"),
        op("post", "/v1/vms/{id}/resume", "Resume vCPUs", VMS).returns("VmRecord"),
        op("post", "/v1/vms/{id}/clone", "Clone a stopped VM", VMS)
            .body("CloneVmRequest")
            .returns("VmRecord")
            .status("201"),
        op(
            "post",
            "/v1/vms/{id}/fork",
            "Fork a running flux-vm VM into N running copies",
            VMS,
        )
        .body("ForkVmRequest")
        .returns("VmList")
        .status("201"),
        op(
            "post",
            "/v1/vms/{id}/backup",
            "Export the root disk to state_dir/backups",
            VMS,
        )
        .body("BackupVmRequest")
        .returns("BackupResult")
        .status("201"),
        op(
            "post",
            "/v1/vms/{id}/restore-backup",
            "Restore a backup into the stopped VM in place",
            VMS,
        )
        .body("RestoreBackupRequest")
        .returns("RestoreBackupResult"),
        op(
            "get",
            "/v1/backups",
            "Backups under state_dir/backups, newest first",
            VMS,
        )
        .returns("BackupList"),
        op("delete", "/v1/backups/{name}", "Delete a backup", VMS).status("204"),
        op(
            "get",
            "/v1/vms/{id}/logs",
            "Console log (text; ?follow=true streams)",
            VMS,
        ),
        op(
            "get",
            "/v1/vms/{id}/serial",
            "Serial console websocket (raw bytes)",
            VMS,
        ),
        op(
            "get",
            "/v1/vms/{id}/console",
            "Guest-agent PTY websocket",
            VMS,
        ),
        op(
            "post",
            "/v1/vms/{id}/snapshot",
            "Save an internal snapshot",
            SNAPSHOTS,
        )
        .body("SnapshotRequest"),
        op("get", "/v1/vms/{id}/snapshots", "List snapshots", SNAPSHOTS).returns("SnapshotList"),
        op(
            "delete",
            "/v1/vms/{id}/snapshots/{tag}",
            "Delete a snapshot",
            SNAPSHOTS,
        )
        .status("204"),
        op(
            "post",
            "/v1/vms/{id}/start-from-snapshot",
            "Start from a snapshot tag",
            SNAPSHOTS,
        )
        .body("SnapshotRequest")
        .returns("VmRecord"),
        op("get", "/v1/vms/{id}/disks", "Root and data disks", DISKS).returns("DiskList"),
        op(
            "post",
            "/v1/vms/{id}/disks",
            "Create a data disk, or attach an existing image/block device (hot-added if running)",
            DISKS,
        )
        .body("AttachDiskRequest")
        .returns("VmDiskInfo")
        .status("201"),
        op(
            "patch",
            "/v1/vms/{id}/disks/{name}",
            "Grow a disk (name `root` for the boot disk)",
            DISKS,
        )
        .body("ResizeDiskRequest")
        .returns("VmDiskInfo"),
        op(
            "delete",
            "/v1/vms/{id}/disks/{name}",
            "Detach a data disk (deletes it unless attached from an existing image)",
            DISKS,
        )
        .status("204"),
        op("get", "/v1/vm-templates", "List VM templates", TEMPLATES).returns("TemplateList"),
        op("post", "/v1/vm-templates", "Save a VM template", TEMPLATES)
            .body("SaveTemplateRequest")
            .returns("VmTemplate")
            .status("201"),
        op(
            "get",
            "/v1/vm-templates/{name}",
            "Get a VM template",
            TEMPLATES,
        )
        .returns("VmTemplate"),
        op(
            "delete",
            "/v1/vm-templates/{name}",
            "Delete a VM template",
            TEMPLATES,
        )
        .status("204"),
        op(
            "post",
            "/v1/vm-templates/{name}/instantiate",
            "Create a VM from a template",
            TEMPLATES,
        )
        .body("InstantiateTemplateRequest")
        .returns("VmRecord")
        .status("201"),
        op("get", "/v1/events", "Lifecycle events", EVENTS)
            .returns("EventList")
            .query(&[
                ("vm", "VM id"),
                ("event", "Event-name prefix"),
                ("since", "RFC 3339 timestamp"),
                ("limit", "Newest N (default 500)"),
            ]),
        op(
            "get",
            "/v1/events/stream",
            "Lifecycle events as Server-Sent Events",
            EVENTS,
        ),
    ]
}

fn schemas() -> Value {
    let obj =
        |desc: &str| json!({"type": "object", "description": desc, "additionalProperties": true});
    let list = |item: &str| json!({"type": "object", "properties": {"items": {"type": "array", "items": {"$ref": format!("#/components/schemas/{item}")}}}});
    json!({
        "VmRecord": obj("A VM: id, name, status, backend, request, labels, workspace, guest_ip, ..."),
        "CreateVmRequest": obj("VM spec: name, backend, image, vcpus, memory_mib, network, cloud_init, ..."),
        "VmList": list("VmRecord"),
        "VmPatch": {"type": "object", "properties": {
            "name": {"type": "string"},
            "labels": {"type": "object", "additionalProperties": {"type": ["string", "null"]}}
        }},
        "CloneVmRequest": {"type": "object", "required": ["name"], "properties": {"name": {"type": "string"}}},
        "ForkVmRequest": {"type": "object", "properties": {"count": {"type": "integer", "minimum": 1, "maximum": 32, "default": 1}, "namePrefix": {"type": "string"}}},
        "BackupVmRequest": {"type": "object", "properties": {
            "compress": {"type": "boolean"},
            "all_disks": {"type": "boolean", "description": "Also back up data disks into a directory"},
            "quiesce": {"type": "string", "enum": ["auto", "required", "never"], "default": "auto",
                "description": "Freeze guest filesystems through the guest agent around the snapshot; auto falls back to crash-consistent"}
        }},
        "RestoreBackupRequest": {"type": "object", "required": ["name"], "properties": {
            "name": {"type": "string", "description": "Backup name from GET /v1/backups"}
        }},
        "RestoreBackupResult": {"type": "object", "properties": {
            "vm_id": {"type": "string", "format": "uuid"},
            "backup": {"type": "string"},
            "restored": {"type": "array", "items": {"type": "string"}},
            "skipped": {"type": "array", "items": {"type": "object"}}
        }},
        "BackupList": list("BackupResult"),
        "BackupResult": {"type": "object", "properties": {
            "vm_id": {"type": "string", "format": "uuid"},
            "path": {"type": "string"},
            "size_bytes": {"type": "integer"},
            "live": {"type": "boolean"},
            "disks": {"type": "array", "items": {"type": "object", "properties": {
                "name": {"type": "string"}, "path": {"type": "string"}, "size_bytes": {"type": "integer"}
            }}}
        }},
        "VmTemplate": {"type": "object", "properties": {
            "name": {"type": "string"},
            "description": {"type": ["string", "null"]},
            "created_at": {"type": "string", "format": "date-time"},
            "spec": {"$ref": "#/components/schemas/CreateVmRequest"}
        }},
        "TemplateList": list("VmTemplate"),
        "SaveTemplateRequest": {"type": "object", "required": ["name", "spec"], "properties": {
            "name": {"type": "string"},
            "description": {"type": "string"},
            "spec": {"$ref": "#/components/schemas/CreateVmRequest"},
            "replace": {"type": "boolean"}
        }},
        "InstantiateTemplateRequest": {"type": "object", "required": ["name"], "properties": {
            "name": {"type": "string"},
            "labels": {"type": "object", "additionalProperties": {"type": "string"}}
        }},
        "SnapshotRequest": {"type": "object", "required": ["tag"], "properties": {"tag": {"type": "string"}}},
        "VmSnapshotInfo": {"type": "object", "properties": {
            "tag": {"type": "string"},
            "created_at": {"type": ["string", "null"], "format": "date-time"},
            "size_bytes": {"type": "integer"}
        }},
        "SnapshotList": list("VmSnapshotInfo"),
        "VmDiskInfo": {"type": "object", "properties": {
            "name": {"type": "string"},
            "path": {"type": "string"},
            "bus": {"type": "string", "enum": ["virtio", "scsi"]},
            "format": {"type": "string"},
            "size_bytes": {"type": "integer"},
            "allocated_bytes": {"type": "integer"}
        }},
        "DiskList": list("VmDiskInfo"),
        "AttachDiskRequest": {"type": "object", "required": ["name"], "description": "Exactly one of size_gib or path", "properties": {
            "name": {"type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,31}$"},
            "size_gib": {"type": "integer", "minimum": 1, "description": "Create a new qcow2 disk of this size"},
            "path": {"type": "string", "description": "Attach this existing qcow2/raw file or block device; detach leaves it in place"}
        }},
        "ResizeDiskRequest": {"type": "object", "required": ["size_gib"], "properties": {
            "size_gib": {"type": "integer", "minimum": 1}
        }},
        "VmEvent": obj("ts, event, vm_id and event-specific fields"),
        "EventList": list("VmEvent"),
        "Error": {"type": "object", "properties": {"error": {"type": "string"}}}
    })
}

fn path_params(path: &str) -> Vec<Value> {
    path.split('/')
        .filter_map(|seg| seg.strip_prefix('{')?.strip_suffix('}'))
        .map(|name| {
            let schema = if name == "id" {
                json!({"type": "string", "format": "uuid"})
            } else {
                json!({"type": "string"})
            };
            json!({"name": name, "in": "path", "required": true, "schema": schema})
        })
        .collect()
}

pub fn spec() -> Value {
    let mut paths: Map<String, Value> = Map::new();
    for o in ops() {
        let mut params = path_params(o.path);
        params.extend(o.query.iter().map(|(name, desc)| {
            json!({"name": name, "in": "query", "required": false, "description": desc, "schema": {"type": "string"}})
        }));
        let mut ok = json!({"description": "OK"});
        if let Some(r) = o.response {
            ok["content"] = json!({"application/json": {"schema": {"$ref": format!("#/components/schemas/{r}")}}});
        }
        let err = json!({"description": "Error", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Error"}}}});
        let mut operation = json!({
            "summary": o.summary,
            "tags": [o.tag],
            "parameters": params,
            "responses": {o.status: ok, "default": err},
        });
        if let Some(b) = o.body {
            operation["requestBody"] = json!({
                "required": true,
                "content": {"application/json": {"schema": {"$ref": format!("#/components/schemas/{b}")}}}
            });
        }
        if matches!(o.path, "/healthz" | "/readyz") {
            operation["security"] = json!([]);
        }
        paths
            .entry(o.path)
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .expect("path item is an object")
            .insert(o.method.into(), operation);
    }
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "Zyvor FluxVM API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "VM lifecycle, disks, snapshots and events. Other /v1 routes exist; this document covers the VM surface."
        },
        "servers": [{"url": "/"}],
        "security": [{"bearer": []}],
        "tags": [
            {"name": VMS}, {"name": SNAPSHOTS}, {"name": DISKS}, {"name": TEMPLATES},
            {"name": EVENTS}, {"name": HOST}
        ],
        "paths": paths,
        "components": {
            "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
            "schemas": schemas()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_is_consistent() {
        let s = spec();
        assert_eq!(s["openapi"], "3.1.0");
        let schemas = s["components"]["schemas"].as_object().unwrap();
        let paths = s["paths"].as_object().unwrap();
        for p in [
            "/v1/vms",
            "/v1/vms/{id}",
            "/v1/vms/{id}/disks/{name}",
            "/v1/events",
        ] {
            assert!(paths.contains_key(p), "{p}");
        }
        assert!(paths["/v1/vms/{id}"].get("patch").is_some());
        let text = s.to_string();
        for (i, _) in text.match_indices("#/components/schemas/") {
            let name: String = text[i + 21..]
                .chars()
                .take_while(|c| c.is_alphanumeric())
                .collect();
            assert!(schemas.contains_key(&name), "dangling $ref {name}");
        }
        for (path, item) in paths {
            let declared = path.matches('{').count();
            for (_, op) in item.as_object().unwrap() {
                let n = op["parameters"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|p| p["in"] == "path")
                    .count();
                assert_eq!(n, declared, "{path}");
            }
        }
    }
}
