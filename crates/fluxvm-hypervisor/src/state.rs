// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::api::BootConfig;
use crate::guest::GuestHandle;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmLifecycle {
    Created,
    Running,
    Paused,
    Stopped,
}

impl VmLifecycle {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Stopped => "stopped",
        }
    }
}

pub struct VmState {
    pub lifecycle: VmLifecycle,
    pub boot: Option<BootConfig>,
    pub last_activity: DateTime<Utc>,
    pub marker: Option<std::path::PathBuf>,
    pub guest: Option<GuestHandle>,
}

impl VmState {
    pub fn new() -> Self {
        Self {
            lifecycle: VmLifecycle::Created,
            boot: None,
            last_activity: Utc::now(),
            marker: None,
            guest: None,
        }
    }

    pub fn touch(&mut self) {
        self.last_activity = Utc::now();
    }

    pub fn pause(&mut self) -> Result<(), String> {
        if self.lifecycle != VmLifecycle::Running {
            return Err(format!("cannot pause from {}", self.lifecycle.as_str()));
        }
        self.lifecycle = VmLifecycle::Paused;
        self.touch();
        Ok(())
    }

    pub fn resume(&mut self) -> Result<(), String> {
        if self.lifecycle != VmLifecycle::Paused {
            return Err(format!("cannot resume from {}", self.lifecycle.as_str()));
        }
        self.lifecycle = VmLifecycle::Running;
        self.touch();
        Ok(())
    }

    pub async fn shutdown_guest(&mut self) {
        if let Some(g) = self.guest.take() {
            let _ = g.shutdown().await;
        }
        if let Some(m) = self.marker.take() {
            let _ = std::fs::remove_file(m);
        }
        self.lifecycle = VmLifecycle::Stopped;
        self.touch();
    }

    pub fn shutdown(&mut self) {
        if let Some(mut g) = self.guest.take() {
            g.kill();
        }
        if let Some(m) = self.marker.take() {
            let _ = std::fs::remove_file(m);
        }
        self.lifecycle = VmLifecycle::Stopped;
        self.touch();
    }
}
