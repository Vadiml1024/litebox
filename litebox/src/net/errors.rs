//! Possible errors from [`Network`]

use core::net::SocketAddr;

use super::local_ports::LocalPortAllocationError;

#[expect(
    unused_imports,
    reason = "used for doc string links to work out, but not for code"
)]
use super::Network;

use thiserror::Error;

/// Possible errors from [`Network::socket`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum SocketError {
    #[error("Unsupported protocol {0}")]
    UnsupportedProtocol(u8),
}

/// Possible errors from [`Network::close`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum CloseError {
    #[error("Not a valid open file descriptor")]
    InvalidFd,
}

/// Possible errors from [`Network::connect`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum ConnectError {
    #[error("Not a valid open file descriptor")]
    InvalidFd,
    #[error("Unsupported address {0}")]
    UnsupportedAddress(SocketAddr),
    #[error("Port allocation failed: {0}")]
    PortAllocationFailure(#[from] LocalPortAllocationError),
}

/// Possible errors from [`Network::bind`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum BindError {}

/// Possible errors from [`Network::listen`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum ListenError {}

/// Possible errors from [`Network::accept`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum AcceptError {}

/// Possible errors from [`Network::send`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum SendError {
    #[error("Not a valid open file descriptor")]
    InvalidFd,
    #[error("Socket is in an invalid state")]
    SocketInInvalidState,
}

/// Possible errors from [`Network::receive`]
#[non_exhaustive]
#[derive(Error, Debug)]
pub enum ReceiveError {
    #[error("Not a valid open file descriptor")]
    InvalidFd,
    #[error("Socket is in an invalid state")]
    SocketInInvalidState,
    #[error("Operation finished")]
    OperationFinished,
}
