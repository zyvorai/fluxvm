// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::io;

#[derive(Debug)]
pub enum FluxError {
    Hypervisor(String),
    Memory(String),
    Device { device: &'static str, msg: String },
    Boot(String),
    Network(String),
    Unsupported(String),
    Io(io::Error),
}

impl fmt::Display for FluxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FluxError::Hypervisor(s) => write!(f, "hypervisor: {s}"),
            FluxError::Memory(s) => write!(f, "memory: {s}"),
            FluxError::Device { device, msg } => write!(f, "device '{device}': {msg}"),
            FluxError::Boot(s) => write!(f, "boot: {s}"),
            FluxError::Network(s) => write!(f, "network: {s}"),
            FluxError::Unsupported(s) => write!(f, "unsupported: {s}"),
            FluxError::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for FluxError {}

impl From<io::Error> for FluxError {
    fn from(e: io::Error) -> Self {
        FluxError::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, FluxError>;
