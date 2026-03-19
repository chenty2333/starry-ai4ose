use alloc::sync::{Arc, Weak};
use core::task::Context;

use axerrno::{AxResult, ax_bail};
use axpoll::{IoEvents, PollSet, Pollable};
use axtask::current;
use kspin::SpinNoIrq;
use starry_process::{ProcessGroup, Session};

use crate::task::AsThread;

pub struct JobControl {
    foreground: SpinNoIrq<Weak<ProcessGroup>>,
    session: SpinNoIrq<Weak<Session>>,
    poll_fg: PollSet,
}

impl Default for JobControl {
    fn default() -> Self {
        Self::new()
    }
}

impl JobControl {
    pub fn new() -> Self {
        Self {
            foreground: SpinNoIrq::new(Weak::new()),
            session: SpinNoIrq::new(Weak::new()),
            poll_fg: PollSet::new(),
        }
    }

    pub fn current_in_foreground(&self) -> bool {
        self.foreground
            .lock()
            .upgrade()
            .is_none_or(|pg| Arc::ptr_eq(&current().as_thread().proc_data.proc.group(), &pg))
    }

    pub fn foreground(&self) -> Option<Arc<ProcessGroup>> {
        self.foreground.lock().upgrade()
    }

    pub fn session(&self) -> Option<Arc<Session>> {
        self.session.lock().upgrade()
    }

    pub fn set_foreground(&self, pg: &Arc<ProcessGroup>) -> AxResult<()> {
        let mut guard = self.foreground.lock();
        let weak = Arc::downgrade(pg);
        if Weak::ptr_eq(&weak, &*guard) {
            return Ok(());
        }

        let Some(session) = self.session.lock().upgrade() else {
            ax_bail!(
                OperationNotPermitted,
                "No session associated with job control"
            );
        };
        if !Arc::ptr_eq(&pg.session(), &session) {
            ax_bail!(
                OperationNotPermitted,
                "Process group does not belong to the session"
            );
        }

        *guard = weak;
        drop(guard);
        self.poll_fg.wake();
        Ok(())
    }

    pub fn set_session(&self, session: &Arc<Session>) {
        let mut guard = self.session.lock();
        assert!(guard.upgrade().is_none());
        *guard = Arc::downgrade(session);
    }

    pub fn clear_session(&self, session: &Arc<Session>) -> bool {
        let mut session_guard = self.session.lock();
        let Some(current) = session_guard.upgrade() else {
            return false;
        };
        if !Arc::ptr_eq(&current, session) {
            return false;
        }
        *session_guard = Weak::new();
        drop(session_guard);

        let mut foreground_guard = self.foreground.lock();
        *foreground_guard = Weak::new();
        drop(foreground_guard);

        self.poll_fg.wake();
        true
    }
}

impl Pollable for JobControl {
    fn poll(&self) -> IoEvents {
        let mut events = IoEvents::empty();
        events.set(IoEvents::IN, self.current_in_foreground());
        events
    }

    fn register(&self, context: &mut Context<'_>, events: IoEvents) {
        if events.contains(IoEvents::IN) {
            self.poll_fg.register(context.waker());
        }
    }
}
