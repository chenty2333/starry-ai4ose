mod epoll;
mod poll;
mod select;

use alloc::{sync::Arc, vec::Vec};
use core::{
    sync::atomic::{AtomicBool, Ordering},
    task::Context,
};

use axpoll::{IoEvents, Pollable};

pub use self::{epoll::*, poll::*, select::*};
use crate::{
    file::FileLike,
    lab::{self, EventKind},
};

struct FdPollSet(pub Vec<(Arc<dyn FileLike>, IoEvents)>);
impl Pollable for FdPollSet {
    fn poll(&self) -> IoEvents {
        unreachable!()
    }

    fn register(&self, context: &mut Context<'_>, _events: IoEvents) {
        for (file, events) in &self.0 {
            file.register(context, *events);
        }
    }
}

struct ObservedPollable<'a> {
    inner: &'a dyn Pollable,
    waited: AtomicBool,
    arg0: usize,
}

impl<'a> ObservedPollable<'a> {
    fn new(inner: &'a dyn Pollable, arg0: usize) -> Self {
        Self {
            inner,
            waited: AtomicBool::new(false),
            arg0,
        }
    }

    fn did_wait(&self) -> bool {
        self.waited.load(Ordering::Acquire)
    }
}

impl Pollable for ObservedPollable<'_> {
    fn poll(&self) -> IoEvents {
        self.inner.poll()
    }

    fn register(&self, context: &mut Context<'_>, events: IoEvents) {
        if self
            .waited
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            lab::emit(EventKind::PollSleep, self.arg0, 0);
        }
        self.inner.register(context, events);
    }
}
