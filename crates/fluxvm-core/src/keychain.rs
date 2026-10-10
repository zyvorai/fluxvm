// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Secrets kept in the macOS login Keychain as generic-password items, read with `/usr/bin/security` so no secret
//! has to sit in a config file. The value is never logged or put into an error message.

use anyhow::{Context, Result, bail};
use std::process::{Command, Stdio};

/// The password of the generic-password item `service` / `account`.
pub fn read_password(service: &str, account: &str) -> Result<String> {
    if service.is_empty() || account.is_empty() {
        bail!("a Keychain item needs a service and an account");
    }
    let out = Command::new("/usr/bin/security")
        .args(["find-generic-password", "-s", service, "-a", account, "-w"])
        .stdin(Stdio::null())
        .output()
        .context("running /usr/bin/security (the Keychain is only available on macOS)")?;
    if !out.status.success() {
        bail!(
            "no Keychain password for service {service:?}, account {account:?} ({}); add it with \
             `security add-generic-password -s {service} -a {account} -w`",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let password = String::from_utf8(out.stdout)
        .context("Keychain password is not UTF-8")?
        .trim_end_matches('\n')
        .to_string();
    if password.is_empty() {
        bail!("Keychain item {service:?} / {account:?} has an empty password");
    }
    Ok(password)
}

/// Creates or replaces the generic-password item `service` / `account`. The secret goes through the Security
/// framework, never a command line.
pub fn write_password(service: &str, account: &str, password: &str) -> Result<()> {
    if service.is_empty() || account.is_empty() {
        bail!("a Keychain item needs a service and an account");
    }
    #[cfg(target_os = "macos")]
    {
        security_framework::passwords::set_generic_password(service, account, password.as_bytes())
            .map_err(|e| anyhow::anyhow!("writing Keychain item {service:?} / {account:?}: {e}"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = password;
        bail!("the Keychain is only available on macOS")
    }
}

/// Removes the generic-password item `service` / `account`; `false` if there was none.
pub fn delete_password(service: &str, account: &str) -> Result<bool> {
    if service.is_empty() || account.is_empty() {
        bail!("a Keychain item needs a service and an account");
    }
    #[cfg(target_os = "macos")]
    {
        const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
        match security_framework::passwords::delete_generic_password(service, account) {
            Ok(()) => Ok(true),
            Err(e) if e.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(false),
            Err(e) => bail!("deleting Keychain item {service:?} / {account:?}: {e}"),
        }
    }
    #[cfg(not(target_os = "macos"))]
    bail!("the Keychain is only available on macOS")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_a_service_and_an_account() {
        assert!(read_password("", "me").is_err());
        assert!(read_password("svc", "").is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "writes to the login Keychain"]
    fn writes_reads_and_deletes_an_item() {
        let (svc, acct) = ("fluxvm-test-keychain-roundtrip", "tester");
        write_password(svc, acct, "s3cr\"et pa$$").unwrap();
        write_password(svc, acct, "replaced").unwrap();
        assert_eq!(read_password(svc, acct).unwrap(), "replaced");
        assert!(delete_password(svc, acct).unwrap());
        assert!(!delete_password(svc, acct).unwrap());
    }

    #[test]
    fn a_missing_item_explains_how_to_add_it() {
        let err = format!(
            "{:#}",
            read_password("fluxvm-test-no-such-item-7c1f", "nobody").unwrap_err()
        );
        assert!(
            err.contains("add-generic-password") || err.contains("only available on macOS"),
            "{err}"
        );
    }
}
