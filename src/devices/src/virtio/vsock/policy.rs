//! Where a guest's impersonated socket may go, decided by whoever made the device.
//!
//! Every TSI request that would put a host socket somewhere -- a `connect`, a datagram's
//! destination, a `listen` -- passes through the muxer before any proxy acts on it, and
//! this is what the muxer asks. With no policy the requests go through as the guest wrote
//! them, which is what TSI has always done.
//!
//! An answer is an address and not a yes: the host end may carry a guest's request
//! somewhere other than where the guest asked, and the guest never learns it did -- a
//! datagram's reply is stamped with the address the guest sent to, and a connection is a
//! stream whichever address is behind it.

use std::net::SocketAddr;

/// The decision a [`Vsock`](super::Vsock) defers to, consulted once per request.
///
/// AF_UNIX requests are not put to it: they name paths on the host, not addresses, and
/// are refused or allowed by [`TsiFlags::HIJACK_UNIX`](super::TsiFlags) alone.
pub trait TsiPolicy: Send + Sync {
    /// Where a guest's `connect` or `sendto` for `to` is carried on the host, or `None` to
    /// refuse it. A refused `connect` is `ECONNREFUSED` in the guest, and a refused datagram
    /// is dropped, the way one sent into a network that does not route it would be.
    fn connect(&self, to: SocketAddr) -> Option<SocketAddr>;

    /// Where on the host a guest's `listen` at `at` binds, or `None` to keep it inside the
    /// guest. `None` is not a failure: the guest kernel takes `EPERM` as a sign to listen on
    /// its own stack instead, so the socket still works for the guest and only the host
    /// cannot reach it.
    fn listen(&self, at: SocketAddr) -> Option<SocketAddr>;
}
