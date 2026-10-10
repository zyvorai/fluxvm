// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Screenshots and keyboard/mouse input for the display of a running `vz` VM (Linux or macOS guest), for agents that
//! drive a guest's GUI or text console, and a per-VM sign-in kept in the host's Keychain that is typed into the guest
//! without the agent ever seeing it.

use crate::VmManager;
use anyhow::{Context, Result, bail};
pub use fluxvm_apple::screen::{InputAction, Screenshot};
use fluxvm_core::model::{BackendKind, VmRecord, VmStatus};
use uuid::Uuid;

/// Keychain service of the per-VM sign-in items; the account is the VM's UUID.
pub const SIGNIN_SERVICE: &str = "dev.zyvor.fluxvm.vm-signin";
const MAX_SIGNIN_CHARS: usize = 256;

#[derive(serde::Serialize, serde::Deserialize)]
struct Signin {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    username: Option<String>,
    password: String,
}

/// What is known about a VM's stored sign-in; never the password.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SigninStatus {
    pub configured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

/// How `vm_signin` fills in the guest's login prompt.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigninMode {
    /// The password only (a macOS login window or lock screen with the user already chosen).
    #[default]
    Password,
    /// Username, Enter, password: a text console or a greeter that asks one field at a time.
    Username,
    /// Username, Tab, password: a form with both fields.
    UsernameTab,
}

fn check_typeable(what: &str, s: &str) -> Result<()> {
    if s.is_empty() {
        bail!("{what} is empty");
    }
    if s.chars().count() > MAX_SIGNIN_CHARS {
        bail!("{what} is longer than {MAX_SIGNIN_CHARS} characters");
    }
    if !s.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
        bail!(
            "{what} can only use printable ASCII and spaces (it is typed on a US keyboard layout)"
        );
    }
    Ok(())
}

fn type_action(text: &str) -> InputAction {
    InputAction::Type { text: text.into() }
}

fn key_action(key: &str) -> InputAction {
    InputAction::Key {
        key: key.into(),
        modifiers: vec![],
    }
}

impl VmManager {
    async fn vz_display_vm(&self, id: Uuid) -> Result<VmRecord> {
        let vm = self.get(id).await?;
        if vm.backend != BackendKind::Vz {
            bail!("screenshots and input are a vz backend feature");
        }
        if vm.status != VmStatus::Running {
            bail!("the VM is {:?}; start it first", vm.status);
        }
        Ok(vm)
    }

    /// The guest display as a PNG, scaled down to `max_width` pixels wide if it is wider.
    pub async fn vm_screenshot(&self, id: Uuid, max_width: Option<u32>) -> Result<Screenshot> {
        if max_width.is_some_and(|w| !(64..=8192).contains(&w)) {
            bail!("max_width must be 64-8192");
        }
        let vm = self.vz_display_vm(id).await?;
        fluxvm_apple::screen::screenshot(&vm, max_width).await
    }

    /// Sends keyboard and mouse `actions` to the guest display in order; returns how many ran.
    pub async fn vm_input(&self, id: Uuid, actions: &[InputAction]) -> Result<usize> {
        let vm = self.vz_display_vm(id).await?;
        let n = fluxvm_apple::screen::input(&vm, actions).await?;
        tracing::info!(vm = %id, actions = n, "display input");
        Ok(n)
    }

    async fn vz_vm(&self, id: Uuid) -> Result<VmRecord> {
        let vm = self.get(id).await?;
        if vm.backend != BackendKind::Vz {
            bail!("a stored sign-in is a vz backend feature");
        }
        Ok(vm)
    }

    /// Stores the sign-in typed by `vm_signin` in the login Keychain, replacing any earlier one.
    pub async fn set_vm_signin(
        &self,
        id: Uuid,
        username: Option<String>,
        password: String,
    ) -> Result<SigninStatus> {
        self.vz_vm(id).await?;
        if let Some(u) = &username {
            check_typeable("username", u)?;
        }
        check_typeable("password", &password)?;
        let secret = serde_json::to_string(&Signin {
            username: username.clone(),
            password,
        })?;
        let account = id.to_string();
        tokio::task::spawn_blocking(move || {
            fluxvm_core::keychain::write_password(SIGNIN_SERVICE, &account, &secret)
        })
        .await
        .context("writing the Keychain")??;
        tracing::info!(vm = %id, "stored sign-in");
        Ok(SigninStatus {
            configured: true,
            username,
        })
    }

    async fn read_signin(&self, id: Uuid) -> Result<Option<Signin>> {
        let account = id.to_string();
        let found = tokio::task::spawn_blocking(move || {
            fluxvm_core::keychain::read_password(SIGNIN_SERVICE, &account)
        })
        .await
        .context("reading the Keychain")?;
        match found {
            Ok(secret) => Ok(Some(
                serde_json::from_str(&secret).context("the stored sign-in is not readable")?,
            )),
            Err(_) => Ok(None),
        }
    }

    pub async fn vm_signin_status(&self, id: Uuid) -> Result<SigninStatus> {
        self.vz_vm(id).await?;
        Ok(match self.read_signin(id).await? {
            Some(s) => SigninStatus {
                configured: true,
                username: s.username,
            },
            None => SigninStatus {
                configured: false,
                username: None,
            },
        })
    }

    /// Removes the stored sign-in; `false` if there was none.
    pub async fn delete_vm_signin(&self, id: Uuid) -> Result<bool> {
        let account = id.to_string();
        tokio::task::spawn_blocking(move || {
            fluxvm_core::keychain::delete_password(SIGNIN_SERVICE, &account)
        })
        .await
        .context("writing the Keychain")?
    }

    /// Types the stored sign-in into the guest's login prompt. The password goes from the Keychain straight to the
    /// runner; it is not returned or logged.
    pub async fn vm_signin(&self, id: Uuid, mode: SigninMode, submit: bool) -> Result<()> {
        let vm = self.vz_display_vm(id).await?;
        let s = self
            .read_signin(id)
            .await?
            .context("no sign-in stored for this VM; set one with `fluxctl signin set`")?;
        if mode != SigninMode::Password {
            let user = s
                .username
                .as_deref()
                .context("the stored sign-in has no username")?;
            let next = if mode == SigninMode::Username {
                "enter"
            } else {
                "tab"
            };
            fluxvm_apple::screen::input(&vm, &[type_action(user), key_action(next)]).await?;
            if mode == SigninMode::Username {
                // The guest needs a moment to show its password prompt.
                tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            }
        }
        let mut actions = vec![type_action(&s.password)];
        if submit {
            actions.push(key_action("enter"));
        }
        fluxvm_apple::screen::input(&vm, &actions)
            .await
            .map_err(|_| anyhow::anyhow!("typing the stored password failed"))?;
        tracing::info!(vm = %id, ?mode, "typed stored sign-in");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_in_fields_must_be_typeable() {
        assert!(check_typeable("password", "Fl#x-Pass_9 ok").is_ok());
        assert!(check_typeable("password", "").is_err());
        assert!(check_typeable("password", "pässword").is_err());
        assert!(check_typeable("password", "tab\there").is_err());
        assert!(check_typeable("password", &"x".repeat(MAX_SIGNIN_CHARS + 1)).is_err());
    }

    #[test]
    fn status_never_carries_the_password() {
        let v = serde_json::to_value(SigninStatus {
            configured: true,
            username: Some("velora".into()),
        })
        .unwrap();
        assert_eq!(
            v,
            serde_json::json!({"configured": true, "username": "velora"})
        );
    }

    #[test]
    fn modes_parse_from_snake_case() {
        let m: SigninMode = serde_json::from_value(serde_json::json!("username_tab")).unwrap();
        assert_eq!(m, SigninMode::UsernameTab);
        assert_eq!(SigninMode::default(), SigninMode::Password);
    }
}
