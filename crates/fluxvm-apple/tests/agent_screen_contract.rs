// SPDX-License-Identifier: Apache-2.0
//! The keys, modifiers and actions `fluxvm_apple::screen` validates are the ones the runner handles, so a request the
//! Rust side accepts is never refused by the runner. Runs on any OS; the Swift itself is compiled only on macOS.
use fluxvm_apple::screen::{MODIFIERS, NAMED_KEYS};
use std::fs;
use std::path::PathBuf;

fn runner(file: &str) -> String {
    fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("runner")
            .join(file),
    )
    .unwrap()
}

/// The Swift declaration of `name`, up to the blank line after it.
fn table(src: &str, name: &str) -> String {
    let start = src.find(name).unwrap_or_else(|| panic!("{name} not found"));
    let rest = &src[start..];
    rest[..rest.find("\n\n").unwrap_or(rest.len())].to_string()
}

#[test]
fn runner_handles_screenshot_and_input_commands() {
    let r = runner("Runner.swift");
    assert!(r.contains("case \"screenshot\":"));
    assert!(r.contains("case \"input\":"));
    assert!(r.contains("\"max_width\""));
}

#[test]
fn every_named_key_and_modifier_is_mapped_by_the_runner() {
    let s = runner("AgentScreen.swift");
    let keys = table(&s, "fluxNamedKeys");
    let missing: Vec<_> = NAMED_KEYS
        .iter()
        .filter(|k| !keys.contains(&format!("\"{k}\":")))
        .collect();
    assert!(missing.is_empty(), "runner has no key code for {missing:?}");
    let mods = table(&s, "fluxModifiers");
    let missing: Vec<_> = MODIFIERS
        .iter()
        .filter(|m| !mods.contains(&format!("\"{m}\":")))
        .collect();
    assert!(missing.is_empty(), "runner has no modifier {missing:?}");
}

#[test]
fn every_input_action_is_handled_by_the_runner() {
    let s = runner("AgentScreen.swift");
    for action in [
        "type",
        "key",
        "move",
        "click",
        "double_click",
        "right_click",
        "middle_click",
        "down",
        "up",
        "drag",
        "scroll",
    ] {
        let tagged = serde_json::json!({"action": action, "x": 1, "y": 1, "to_x": 2, "to_y": 2, "text": "a", "key": "a"});
        assert!(
            serde_json::from_value::<fluxvm_apple::screen::InputAction>(tagged).is_ok(),
            "Rust does not accept {action}"
        );
        assert!(
            s.contains(&format!("\"{action}\"")),
            "runner does not handle {action}"
        );
    }
}
