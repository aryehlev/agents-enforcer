//! Event definitions for agent gateway enforcer

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Events emitted by the enforcer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    /// Network connection was blocked
    NetworkBlocked(NetworkBlockedEvent),
    /// Network connection was allowed
    NetworkAllowed(NetworkAllowedEvent),
    /// File access was blocked
    FileBlocked(FileBlockedEvent),
    /// File access was allowed
    FileAllowed(FileAllowedEvent),
    /// Backend state changed
    BackendStateChanged(BackendStateChangedEvent),
}

/// Network connection blocked event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkBlockedEvent {
    /// Timestamp
    pub timestamp: i64,
    /// Destination IP
    pub dst_ip: IpAddr,
    /// Destination port
    pub dst_port: u16,
    /// Protocol
    pub protocol: Protocol,
    /// Process ID
    pub pid: Option<u32>,
}

/// Network connection allowed event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkAllowedEvent {
    /// Timestamp
    pub timestamp: i64,
    /// Destination IP
    pub dst_ip: IpAddr,
    /// Destination port
    pub dst_port: u16,
    /// Protocol
    pub protocol: Protocol,
    /// Process ID
    pub pid: Option<u32>,
}

/// File access blocked event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBlockedEvent {
    /// Timestamp
    pub timestamp: i64,
    /// File path
    pub path: String,
    /// Access type
    pub access_type: FileAccessType,
    /// Process ID
    pub pid: Option<u32>,
}

/// File access allowed event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileAllowedEvent {
    /// Timestamp
    pub timestamp: i64,
    /// File path
    pub path: String,
    /// Access type
    pub access_type: FileAccessType,
    /// Process ID
    pub pid: Option<u32>,
}

/// Backend state changed event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendStateChangedEvent {
    /// Timestamp
    pub timestamp: i64,
    /// Backend name
    pub backend: String,
    /// Old state
    pub old_state: BackendState,
    /// New state
    pub new_state: BackendState,
}

/// Network protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    /// TCP
    Tcp,
    /// UDP
    Udp,
    /// ICMP
    Icmp,
    /// Other
    Other(u8),
}

/// File access type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FileAccessType {
    /// Read
    Read,
    /// Write
    Write,
    /// Execute
    Execute,
    /// Delete
    Delete,
}

/// Backend state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendState {
    /// Not initialized
    NotInitialized,
    /// Initialized but not running
    Initialized,
    /// Running
    Running,
    /// Stopped
    Stopped,
    /// Error state
    Error,
}
