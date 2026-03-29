use alloc::sync::Arc;

use axerrno::{AxError, AxResult, ax_bail};
use axsync::Mutex;

use crate::{
    listen_table::ListenTable,
    service::Service,
    wrapper::SocketSetWrapper,
};

/// A self-contained network stack instance.
///
/// Each `NetStack` holds its own socket set, listen table, service (interface +
/// router), and ephemeral port counters. Multiple `NetStack` instances can
/// coexist for network namespace isolation.
///
/// **Drop ordering:** `listen_table` is declared before `socket_set` so that
/// listen-table entries (which hold `Weak<SocketSetWrapper>`) are cleaned up
/// while the socket set is still alive.
pub struct NetStack {
    pub(crate) listen_table: Arc<ListenTable>,
    pub(crate) socket_set: Arc<SocketSetWrapper<'static>>,
    pub(crate) service: Mutex<Service>,
    pub(crate) tcp_ephemeral_port: Mutex<u16>,
    pub(crate) udp_ephemeral_port: Mutex<u16>,
}

const PORT_START: u16 = 0xc000;
const PORT_END: u16 = 0xffff;

impl NetStack {
    /// Create a new `NetStack` from pre-built components.
    pub fn new(
        listen_table: Arc<ListenTable>,
        socket_set: Arc<SocketSetWrapper<'static>>,
        service: Service,
    ) -> Arc<Self> {
        Arc::new(Self {
            listen_table,
            socket_set,
            service: Mutex::new(service),
            tcp_ephemeral_port: Mutex::new(PORT_START),
            udp_ephemeral_port: Mutex::new(PORT_START),
        })
    }

    /// Poll all network interfaces owned by this stack.
    pub fn poll_interfaces(&self) {
        while self.service.lock().poll(&mut self.socket_set.inner.lock()) {}
    }

    /// Acquire a lock on the Service.
    pub(crate) fn get_service(&self) -> axsync::MutexGuard<'_, Service> {
        self.service.lock()
    }

    /// Allocate a TCP ephemeral port.
    pub(crate) fn tcp_ephemeral_port(&self) -> AxResult<u16> {
        let mut curr = self.tcp_ephemeral_port.lock();
        let mut tries = 0;
        while tries <= PORT_END - PORT_START {
            let port = *curr;
            if *curr == PORT_END {
                *curr = PORT_START;
            } else {
                *curr += 1;
            }
            if self.listen_table.can_listen(port) {
                return Ok(port);
            }
            tries += 1;
        }
        ax_bail!(AddrInUse, "no available ports");
    }

    /// Allocate a UDP ephemeral port.
    pub(crate) fn udp_ephemeral_port(&self) -> AxResult<u16> {
        let mut curr = self.udp_ephemeral_port.lock();
        let port = *curr;
        if *curr == PORT_END {
            *curr = PORT_START;
        } else {
            *curr += 1;
        }
        Ok(port)
    }
}
