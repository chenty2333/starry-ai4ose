use alloc::{boxed::Box, sync::Arc};
use core::{
    pin::Pin,
    task::{Context, Waker},
};

use axerrno::{AxError, AxResult};
use axhal::time::{NANOS_PER_MICROS, TimeValue, wall_time_nanos};
use axtask::future::sleep_until;
use smoltcp::{
    iface::{Interface, SocketSet},
    time::Instant,
    wire::{HardwareAddress, IpAddress, IpListenEndpoint},
};

use crate::{router::Router, wrapper::SocketSetWrapper};

fn now() -> Instant {
    Instant::from_micros_const((wall_time_nanos() / NANOS_PER_MICROS) as i64)
}

pub struct Service {
    pub iface: Interface,
    pub(crate) router: Router,
    pub(crate) socket_set: Arc<SocketSetWrapper<'static>>,
    timeout: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}
impl Service {
    pub fn new(mut router: Router, socket_set: Arc<SocketSetWrapper<'static>>) -> Self {
        let config = smoltcp::iface::Config::new(HardwareAddress::Ip);
        let iface = Interface::new(config, &mut router, now());

        Self {
            iface,
            router,
            socket_set,
            timeout: None,
        }
    }

    pub fn poll(&mut self, sockets: &mut SocketSet) -> bool {
        let timestamp = now();

        self.router.poll(timestamp);
        self.iface.poll(timestamp, &mut self.router, sockets);
        self.router.dispatch(timestamp)
    }

    pub fn get_source_address(&self, dst_addr: &IpAddress) -> AxResult<IpAddress> {
        let Some(rule) = self.router.table.lookup(dst_addr) else {
            return Err(AxError::from(axerrno::LinuxError::ENETUNREACH));
        };
        Ok(rule.src)
    }

    pub fn device_mask_for(&self, endpoint: &IpListenEndpoint) -> u64 {
        match endpoint.addr {
            Some(addr) => self
                .router
                .table
                .lookup(&addr)
                .map_or(0, |it| {
                    if it.dev >= 64 {
                        u64::MAX
                    } else {
                        1u64 << it.dev
                    }
                }),
            None => u64::MAX,
        }
    }

    pub fn register_waker(&mut self, mask: u64, waker: &Waker) {
        let next = self.iface.poll_at(now(), &self.socket_set.inner.lock());

        if let Some(t) = next {
            let next = TimeValue::from_micros(t.total_micros() as _);

            // drop old timeout future
            self.timeout = None;

            let mut fut = Box::pin(sleep_until(next));
            let mut cx = Context::from_waker(waker);

            if fut.as_mut().poll(&mut cx).is_ready() {
                waker.wake_by_ref();
                return;
            } else {
                self.timeout = Some(fut);
            }
        }

        for (i, device) in self.router.devices.iter().enumerate() {
            if i >= 64 || mask & (1u64 << i) != 0 {
                device.register_waker(waker);
            }
        }
    }
}
