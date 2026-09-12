//! Inactivity-based session tracking for an unlocked vault view.
//!
//! The TUI holds a `Session` while a vault is unlocked. Every user
//! interaction calls [`Session::record_activity`]; the render/event loop
//! calls [`Session::is_expired`] each tick to decide whether to drop back
//! to the home screen and invalidate the in-memory unlocked state.
//!
//! The timer is built on an injectable [`Clock`] rather than
//! `Instant::now()` directly so tests can assert timeout behavior
//! deterministically without real sleeping.

use std::time::{Duration, Instant};

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Anything that can report "now" as a monotonic instant. Production code
/// uses [`SystemClock`]; tests use a [`ManualClock`] they can advance
/// explicitly.
pub trait Clock {
    fn now(&self) -> Instant;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// A test clock that only advances when told to.
#[derive(Debug, Clone)]
pub struct ManualClock {
    now: Instant,
}

impl ManualClock {
    pub fn new() -> Self {
        ManualClock { now: Instant::now() }
    }

    pub fn advance(&mut self, d: Duration) {
        self.now += d;
    }
}

impl Default for ManualClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Instant {
        self.now
    }
}

/// Tracks the last user-activity timestamp for an unlocked vault session
/// and reports whether it has gone idle past `timeout`.
pub struct Session<C: Clock = SystemClock> {
    clock: C,
    last_activity: Instant,
    timeout: Duration,
}

impl Session<SystemClock> {
    pub fn new() -> Self {
        Session::with_clock(SystemClock)
    }
}

impl Default for Session<SystemClock> {
    fn default() -> Self {
        Self::new()
    }
}

impl<C: Clock> Session<C> {
    pub fn with_clock(clock: C) -> Self {
        let now = clock.now();
        Session { clock, last_activity: now, timeout: DEFAULT_TIMEOUT }
    }

    pub fn with_clock_and_timeout(clock: C, timeout: Duration) -> Self {
        let now = clock.now();
        Session { clock, last_activity: now, timeout }
    }

    /// Resets the inactivity timer. Call this on any relevant user
    /// interaction (key press, navigation, etc.).
    pub fn record_activity(&mut self) {
        self.last_activity = self.clock.now();
    }

    pub fn is_expired(&self) -> bool {
        self.clock.now().duration_since(self.last_activity) >= self.timeout
    }

    pub fn idle_for(&self) -> Duration {
        self.clock.now().duration_since(self.last_activity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_session_is_not_expired() {
        let session = Session::with_clock(ManualClock::new());
        assert!(!session.is_expired());
    }

    #[test]
    fn expires_after_timeout_with_no_activity() {
        let mut session = TestableSession::new(Duration::from_secs(30));
        assert!(!session.is_expired());
        session.advance(Duration::from_secs(29));
        assert!(!session.is_expired());
        session.advance(Duration::from_secs(1));
        assert!(session.is_expired());
    }

    #[test]
    fn activity_resets_the_timer() {
        let mut session = TestableSession::new(Duration::from_secs(30));
        session.advance(Duration::from_secs(25));
        assert!(!session.is_expired());
        session.record_activity();
        session.advance(Duration::from_secs(25));
        assert!(!session.is_expired(), "activity should have reset the 30s window");
        session.advance(Duration::from_secs(6));
        assert!(session.is_expired());
    }

    /// Small helper that owns a `ManualClock` alongside the `Session` so
    /// tests can both advance time and query expiry without borrow
    /// conflicts.
    struct TestableSession {
        session: Session<ManualClock>,
    }

    impl TestableSession {
        fn new(timeout: Duration) -> Self {
            let clock = ManualClock::new();
            TestableSession { session: Session::with_clock_and_timeout(clock, timeout) }
        }

        fn advance(&mut self, d: Duration) {
            self.session.clock.advance(d);
        }

        fn is_expired(&self) -> bool {
            self.session.is_expired()
        }

        fn record_activity(&mut self) {
            self.session.record_activity();
        }
    }
}
