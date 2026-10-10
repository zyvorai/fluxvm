// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Agent control of a VM's display: screenshots of the guest console and synthesized keyboard and mouse input. The
//! runner renders the display into an offscreen view and feeds events to it, so this works without a console window and
//! without the Accessibility or Screen Recording permissions a host-level tool would need.

use anyhow::{Context, Result, bail};
use fluxvm_core::model::VmRecord;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Longest text one `type` action may send.
pub const MAX_TYPE_CHARS: usize = 4096;
/// The runner reads one request of at most 4 KiB; text goes in chunks well under that.
const TYPE_CHUNK: usize = 500;

pub const MODIFIERS: &[&str] = &["shift", "control", "option", "command"];

/// Keys `key` accepts besides single printable characters.
pub const NAMED_KEYS: &[&str] = &[
    "enter",
    "return",
    "tab",
    "space",
    "escape",
    "esc",
    "backspace",
    "delete",
    "up",
    "down",
    "left",
    "right",
    "home",
    "end",
    "page_up",
    "page_down",
    "f1",
    "f2",
    "f3",
    "f4",
    "f5",
    "f6",
    "f7",
    "f8",
    "f9",
    "f10",
    "f11",
    "f12",
];

/// One input action. Coordinates are pixels of a screenshot (top-left origin); `screen_width` names the width of the
/// screenshot they refer to when it was scaled down (default: full resolution).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum InputAction {
    /// Types text on a US keyboard layout: printable ASCII, newline and tab.
    Type { text: String },
    /// Presses one key, holding `modifiers` (shift, control, option, command).
    Key {
        key: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        modifiers: Vec<String>,
    },
    Move {
        x: f64,
        y: f64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        screen_width: Option<u32>,
    },
    Click {
        x: f64,
        y: f64,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        modifiers: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        screen_width: Option<u32>,
    },
    DoubleClick {
        x: f64,
        y: f64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        screen_width: Option<u32>,
    },
    RightClick {
        x: f64,
        y: f64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        screen_width: Option<u32>,
    },
    MiddleClick {
        x: f64,
        y: f64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        screen_width: Option<u32>,
    },
    /// Holds the left button down at (x, y); `up` releases it.
    Down {
        x: f64,
        y: f64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        screen_width: Option<u32>,
    },
    Up {
        x: f64,
        y: f64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        screen_width: Option<u32>,
    },
    Drag {
        x: f64,
        y: f64,
        to_x: f64,
        to_y: f64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        screen_width: Option<u32>,
    },
    /// Wheel notches: positive `dy` scrolls down, positive `dx` right; (x, y) moves the pointer first.
    Scroll {
        #[serde(default)]
        dx: i32,
        #[serde(default)]
        dy: i32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        x: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        y: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        screen_width: Option<u32>,
    },
}

impl InputAction {
    /// Rejects what the runner would refuse, before anything is sent, so a batch fails as a whole.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Type { text } => {
                if text.is_empty() {
                    bail!("type needs text");
                }
                if text.chars().count() > MAX_TYPE_CHARS {
                    bail!("type takes at most {MAX_TYPE_CHARS} characters");
                }
                if let Some(c) = text
                    .chars()
                    .find(|c| !(c.is_ascii_graphic() || matches!(c, ' ' | '\n' | '\t')))
                {
                    bail!(
                        "cannot type {c:?}: only printable ASCII, newline and tab (US keyboard layout)"
                    );
                }
            }
            Self::Key { key, modifiers } => {
                let k = key.to_ascii_lowercase();
                let printable = k.chars().count() == 1 && k.chars().all(|c| c.is_ascii_graphic());
                if !printable && !NAMED_KEYS.contains(&k.as_str()) {
                    bail!(
                        "unknown key {key:?}; use a printable character or one of {NAMED_KEYS:?}"
                    );
                }
                check_modifiers(modifiers)?;
            }
            Self::Click { modifiers, .. } => check_modifiers(modifiers)?,
            Self::Scroll { dx, dy, x, y, .. } => {
                if x.is_some() != y.is_some() {
                    bail!("scroll takes both x and y or neither");
                }
                if dx.abs() > 100 || dy.abs() > 100 {
                    bail!("scroll moves at most 100 notches at a time");
                }
            }
            _ => {}
        }
        for (name, v) in self.coordinates() {
            if !v.is_finite() || !(0.0..=100_000.0).contains(&v) {
                bail!("{name} must be a pixel coordinate within the screen");
            }
        }
        Ok(())
    }

    fn coordinates(&self) -> Vec<(&'static str, f64)> {
        match *self {
            Self::Type { .. } | Self::Key { .. } => vec![],
            Self::Move { x, y, .. }
            | Self::Click { x, y, .. }
            | Self::DoubleClick { x, y, .. }
            | Self::RightClick { x, y, .. }
            | Self::MiddleClick { x, y, .. }
            | Self::Down { x, y, .. }
            | Self::Up { x, y, .. } => vec![("x", x), ("y", y)],
            Self::Drag {
                x, y, to_x, to_y, ..
            } => vec![("x", x), ("y", y), ("to_x", to_x), ("to_y", to_y)],
            Self::Scroll { x, y, .. } => x
                .map(|x| ("x", x))
                .into_iter()
                .chain(y.map(|y| ("y", y)))
                .collect(),
        }
    }

    /// The runner requests for this action (long text becomes several).
    fn requests(&self) -> Result<Vec<Value>> {
        if let Self::Type { text } = self {
            let chars: Vec<char> = text.chars().collect();
            return Ok(chars
                .chunks(TYPE_CHUNK)
                .map(|c| json!({"cmd": "input", "action": "type", "text": c.iter().collect::<String>()}))
                .collect());
        }
        let mut v = serde_json::to_value(self)?;
        v["cmd"] = json!("input");
        Ok(vec![v])
    }
}

fn check_modifiers(mods: &[String]) -> Result<()> {
    for m in mods {
        if !MODIFIERS.contains(&m.to_ascii_lowercase().as_str()) {
            bail!("unknown modifier {m:?}; use {MODIFIERS:?}");
        }
    }
    Ok(())
}

async fn send(vm: &VmRecord, request: Value) -> Result<Value> {
    let sock = vm
        .control_socket
        .as_deref()
        .context("VM has no runner control socket recorded")?;
    let reply = crate::control_call_with(sock, request)
        .await
        .context("runner display control")?;
    if !reply.ok() {
        bail!(
            "{}",
            reply.error().unwrap_or("the runner refused the request")
        );
    }
    Ok(reply.0)
}

/// A captured screenshot.
#[derive(Debug, Clone)]
pub struct Screenshot {
    pub png: Vec<u8>,
    pub width: u32,
    pub height: u32,
    /// Every sampled pixel had the same colour: the guest has not drawn anything yet, or its display is off.
    pub blank: bool,
}

/// Captures the guest display as a PNG, scaled down to `max_width` pixels wide if it is wider.
pub async fn screenshot(vm: &VmRecord, max_width: Option<u32>) -> Result<Screenshot> {
    let path = std::env::temp_dir().join(format!("fluxvm-screen-{}.png", uuid::Uuid::new_v4()));
    let mut req = json!({"cmd": "screenshot", "path": path});
    if let Some(w) = max_width {
        req["max_width"] = json!(w);
    }
    let sent = send(vm, req).await;
    let png = tokio::fs::read(&path).await;
    let _ = tokio::fs::remove_file(&path).await;
    let v = sent?;
    let png = png.with_context(|| format!("reading {}", path.display()))?;
    let dim = |k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0) as u32;
    Ok(Screenshot {
        png,
        width: dim("width"),
        height: dim("height"),
        blank: v.get("blank").and_then(Value::as_bool).unwrap_or(false),
    })
}

/// Sends `actions` in order, stopping at the first the runner refuses. All are validated first.
pub async fn input(vm: &VmRecord, actions: &[InputAction]) -> Result<usize> {
    if actions.is_empty() {
        bail!("no input actions");
    }
    if actions.len() > 100 {
        bail!("at most 100 input actions per request");
    }
    for (i, a) in actions.iter().enumerate() {
        a.validate().with_context(|| format!("action {i}"))?;
    }
    for (i, a) in actions.iter().enumerate() {
        for req in a.requests()? {
            send(vm, req).await.with_context(|| format!("action {i}"))?;
        }
    }
    Ok(actions.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(v: Value) -> InputAction {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn actions_round_trip_to_runner_requests() {
        let a = parse(json!({"action": "click", "x": 10, "y": 20, "modifiers": ["command"]}));
        let r = a.requests().unwrap();
        assert_eq!(
            r,
            vec![
                json!({"cmd": "input", "action": "click", "x": 10.0, "y": 20.0, "modifiers": ["command"]})
            ]
        );
        let s = parse(json!({"action": "scroll", "dy": 3}));
        assert_eq!(
            s.requests().unwrap(),
            vec![json!({"cmd": "input", "action": "scroll", "dx": 0, "dy": 3})]
        );
    }

    #[test]
    fn long_text_is_chunked_below_the_runner_read_size() {
        let text: String = "a\"\\".repeat(1000);
        let r = InputAction::Type { text: text.clone() }.requests().unwrap();
        assert_eq!(r.len(), 6);
        assert!(r.iter().all(|v| v.to_string().len() < 4096));
        let joined: String = r.iter().map(|v| v["text"].as_str().unwrap()).collect();
        assert_eq!(joined, text);
    }

    #[test]
    fn validation_rejects_what_the_runner_cannot_send() {
        let bad = [
            json!({"action": "type", "text": ""}),
            json!({"action": "type", "text": "héllo"}),
            json!({"action": "key", "key": "hyper"}),
            json!({"action": "key", "key": "a", "modifiers": ["meta"]}),
            json!({"action": "click", "x": -1, "y": 3}),
            json!({"action": "scroll", "dy": 1, "x": 3}),
            json!({"action": "scroll", "dy": 1000}),
        ];
        for b in bad {
            assert!(parse(b.clone()).validate().is_err(), "{b}");
        }
        let good = [
            json!({"action": "type", "text": "ls -la\n"}),
            json!({"action": "key", "key": "Enter"}),
            json!({"action": "key", "key": "c", "modifiers": ["control"]}),
            json!({"action": "drag", "x": 1, "y": 2, "to_x": 30, "to_y": 40}),
            json!({"action": "scroll", "dy": -2, "x": 5, "y": 6, "screen_width": 1280}),
        ];
        for g in good {
            parse(g.clone()).validate().unwrap();
        }
    }

    #[test]
    fn unknown_actions_and_fields_are_rejected() {
        assert!(serde_json::from_value::<InputAction>(json!({"action": "teleport"})).is_err());
    }
}
