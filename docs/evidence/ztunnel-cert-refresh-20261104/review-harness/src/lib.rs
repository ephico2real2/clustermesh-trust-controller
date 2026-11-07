pub mod time;

// OB2 review harness. `time` is ztunnel d5f24b5 src/time.rs copied verbatim. The `model`
// module lifts the Worker::run scheduling skeleton (PendingPriority, push_increase,
// maybe_sleep_until, the clock_check branch, the fetch-result rescheduling) with the same
// code, minus certificates and the certs map, so the scheduling can be measured offline.
#[cfg(test)]
mod model {
    use crate::time::{Converter, WallClock};
    use keyed_priority_queue::KeyedPriorityQueue;
    use std::cmp::Ordering;
    use std::collections::HashMap;
    use std::hash::{Hash, RandomState};
    use std::time::SystemTime;
    use tokio::sync::mpsc;
    use tokio::time::{Duration, Instant, sleep_until};

    const CLOCK_CHECK_INTERVAL: Duration = Duration::from_secs(5);
    const CLOCK_JUMP_THRESHOLD: Duration = Duration::from_secs(1);
    const SEC: Duration = Duration::from_secs(1);
    const CERT_HALFLIFE: Duration = Duration::from_secs(50);

    #[derive(PartialOrd, PartialEq, Eq, Ord, Debug, Copy, Clone)]
    pub enum Priority {
        Background,
        Warmup,
        RealTime,
    }

    #[derive(Eq, PartialEq, Debug)]
    struct PendingPriority(Priority, Instant);

    impl Ord for PendingPriority {
        fn cmp(&self, other: &Self) -> Ordering {
            match self.0.cmp(&other.0) {
                Ordering::Equal => other.1.cmp(&self.1),
                ne => ne,
            }
        }
    }
    impl PartialOrd for PendingPriority {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    fn push_increase<TKey: Hash + Eq, TPriority: Ord>(
        kp: &mut KeyedPriorityQueue<TKey, TPriority, RandomState>,
        key: TKey,
        priority: TPriority,
    ) {
        if kp.get_priority(&key).is_none_or(|p| priority > *p) {
            kp.push(key, priority);
        }
    }

    async fn maybe_sleep_until(till: Option<Instant>) -> bool {
        match till {
            Some(till) => {
                sleep_until(till).await;
                true
            }
            None => false,
        }
    }

    // The skew computation of the clock_check branch, verbatim, as a pure function.
    fn skew(prev: (Instant, SystemTime), sample: (Instant, SystemTime)) -> (i128, Duration) {
        let monotonic = sample.0.saturating_duration_since(prev.0).as_nanos() as i128;
        let wall = match sample.1.duration_since(prev.1) {
            Ok(d) => d.as_nanos() as i128,
            Err(e) => -(e.duration().as_nanos() as i128),
        };
        let skew = wall - monotonic;
        let jump = Duration::from_nanos(skew.unsigned_abs().try_into().unwrap_or(u64::MAX));
        (skew, jump)
    }

    enum Request {
        Fetch(String, Priority),
    }

    // One "fetch": the mock CA answers after SEC with a certificate whose half-life is
    // CERT_HALFLIFE from issue (issue time = clock.now(), as the mock CA does).
    struct Issued {
        key: String,
        popped_at: Instant,
        issued_wall: SystemTime,
    }

    // The scheduling skeleton of Worker::run for concurrency 1 (the two new tests use
    // setup(1)): one in-flight fetch instead of FuturesUnordered, no certs map.
    async fn run1(
        clock: WallClock,
        requests: mpsc::Receiver<Request>,
        log: std::sync::Arc<std::sync::Mutex<Vec<Issued>>>,
    ) {
        run_mode(clock, requests, log, false).await
    }

    // `legacy` = the 68c0282 scheduler: one Converter taken at start-up maps due -> Instant and
    // there is no clock check (the branch is kept but never reschedules).
    async fn run_mode(
        clock: WallClock,
        mut requests: mpsc::Receiver<Request>,
        log: std::sync::Arc<std::sync::Mutex<Vec<Issued>>>,
        legacy: bool,
    ) {
        let startup_conv = Converter::new();
        let map_due = |due: SystemTime| -> Instant {
            if legacy {
                startup_conv
                    .system_time_to_instant(due)
                    .map(Instant::from_std)
                    .unwrap_or_else(Instant::now)
            } else {
                clock.instant_at(due).unwrap_or_else(Instant::now)
            }
        };
        let mut pending: KeyedPriorityQueue<String, PendingPriority> = KeyedPriorityQueue::new();
        let mut refresh_due: HashMap<String, SystemTime> = HashMap::new();
        let mut in_flight: Option<std::pin::Pin<Box<dyn std::future::Future<Output = (String, SystemTime)> + Send>>> = None;
        let mut clock_check = tokio::time::interval(CLOCK_CHECK_INTERVAL);
        clock_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut clock_sample = (Instant::now(), clock.now());

        'main: loop {
            let next = pending.peek().map(|(_, PendingPriority(_, ts))| *ts);
            let have_fetch = in_flight.is_some();
            tokio::select! {
                res = requests.recv() => match res {
                    Some(Request::Fetch(key, pri)) => {
                        push_increase(&mut pending, key, PendingPriority(pri, Instant::now()));
                    }
                    None => break 'main,
                },
                (key, issued_wall) = async { in_flight.as_mut().unwrap().await }, if have_fetch => {
                    in_flight = None;
                    // Ok path: due = certs.refresh_at() = not_before + lifetime/2.
                    let due = issued_wall + CERT_HALFLIFE;
                    let refresh_at = map_due(due);
                    refresh_due.insert(key.clone(), due);
                    push_increase(&mut pending, key, PendingPriority(Priority::Background, refresh_at));
                },
                _ = clock_check.tick() => {
                    let sample = (Instant::now(), clock.now());
                    let (skew, jump) = skew(clock_sample, sample);
                    clock_sample = sample;
                    if jump < CLOCK_JUMP_THRESHOLD || legacy {
                        continue 'main;
                    }
                    let mut rescheduled = 0usize;
                    for (key, due) in &refresh_due {
                        if let Some(PendingPriority(Priority::Background, _)) = pending.get_priority(key) {
                            let refresh_at = clock.instant_at(*due).unwrap_or_else(Instant::now);
                            let _ = pending.set_priority(key, PendingPriority(Priority::Background, refresh_at));
                            rescheduled += 1;
                        }
                    }
                    let direction = if skew > 0 { "ahead of" } else { "behind" };
                    eprintln!("t={:?} jump={jump:?} rescheduled={rescheduled} wall clock {direction} monotonic", Instant::now());
                },
                true = maybe_sleep_until(next), if !have_fetch => {
                    let (key, _) = pending.pop().expect("pending should always have an element at this point");
                    refresh_due.remove(&key);
                    let popped_at = Instant::now();
                    let clock = clock.clone();
                    let log = log.clone();
                    in_flight = Some(Box::pin(async move {
                        tokio::time::sleep(SEC).await;
                        let issued_wall = clock.now();
                        log.lock().unwrap().push(Issued { key: key.clone(), popped_at, issued_wall });
                        (key, issued_wall)
                    }));
                },
            }
        }
    }

    fn setup() -> (WallClock, mpsc::Sender<Request>, std::sync::Arc<std::sync::Mutex<Vec<Issued>>>, tokio::task::JoinHandle<()>) {
        let clock = WallClock::simulated(Converter::new());
        let (tx, rx) = mpsc::channel(10);
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let h = tokio::spawn(run1(clock.clone(), rx, log.clone()));
        (clock, tx, log, h)
    }

    fn setup_legacy() -> (WallClock, mpsc::Sender<Request>, std::sync::Arc<std::sync::Mutex<Vec<Issued>>>, tokio::task::JoinHandle<()>) {
        let clock = WallClock::simulated(Converter::new());
        let (tx, rx) = mpsc::channel(10);
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let h = tokio::spawn(run_mode(clock.clone(), rx, log.clone(), true));
        (clock, tx, log, h)
    }

    // Discrimination: the same steps as test_refresh_follows_wall_clock_jump against the 68c0282
    // scheduler. The refresh stays on the stale Instant (t=51 s), so the new test's
    // `fetches().len() == 1` at t=8 s would fail there.
    #[tokio::test(start_paused = true)]
    async fn model_legacy_scheduler_misses_the_jump() {
        let start = Instant::now();
        let (clock, tx, log, h) = setup_legacy();
        tx.send(Request::Fetch("k".into(), Priority::RealTime)).await.unwrap();
        tokio::time::sleep(SEC + Duration::from_millis(1)).await;
        assert_eq!(log.lock().unwrap().len(), 1);
        clock.step_forward(4 * CERT_HALFLIFE);
        tokio::time::sleep(CLOCK_CHECK_INTERVAL + 2 * SEC).await;
        let n_at_8s = log.lock().unwrap().len();
        tokio::time::sleep(CERT_HALFLIFE).await;
        let l = log.lock().unwrap();
        eprintln!("legacy: fetches at t=8s: {} (new test asserts 2 incl. initial -> 1 after clear); refresh popped at t={:?}", n_at_8s, l.get(1).map(|i| i.popped_at.duration_since(start)));
        assert_eq!(n_at_8s, 1, "legacy scheduler must NOT have refreshed by t=8 s");
        assert_eq!(l.len(), 2);
        drop(l);
        drop(tx);
        h.await.unwrap();
    }

    // --- claim 3: the start_fetch_key expired-branch race, at the watch-channel level --------
    //
    // CertChannel keeps an rx that never observes sends, so every clone sees the latest value as
    // "changed" and wait() returns it at once. The expired branch calls borrow_and_update() on
    // the clone so wait() blocks for the NEXT send. If the worker's send lands between
    // expired() and borrow_and_update(), the fresh value is marked seen and the caller waits for
    // a further send (a redundant fetch). The "fixed" pattern decides on the value that
    // borrow_and_update() returns and un-sees it with mark_changed() when it is not expired.
    #[derive(Debug, Clone, PartialEq)]
    enum St {
        Initializing,
        Available { not_after: u64 },
    }

    fn expired(rx: &tokio::sync::watch::Receiver<St>, now: u64) -> bool {
        matches!(*rx.borrow(), St::Available { not_after } if not_after <= now)
    }

    #[tokio::test(start_paused = true)]
    async fn watch_race_current_pattern_waits_past_the_fresh_value() {
        let (tx, stored_rx) = tokio::sync::watch::channel(St::Initializing);
        tx.send(St::Available { not_after: 100 }).unwrap(); // the cached, now expired, cert
        let now = 150;
        let mut rx = stored_rx.clone();
        // d5f24b5 start_fetch_key: check, then mark seen.
        assert!(expired(&rx, now));
        tx.send(St::Available { not_after: 250 }).unwrap(); // worker's refresh lands here
        rx.borrow_and_update(); // marks the FRESH value seen
        // wait(): changed() now blocks although a fresh certificate is cached.
        let r = tokio::time::timeout(Duration::from_secs(1), rx.changed()).await;
        assert!(r.is_err(), "current pattern: the caller does not get the fresh cert without another send");
    }

    #[tokio::test(start_paused = true)]
    async fn watch_race_fixed_pattern_returns_the_fresh_value() {
        let (tx, stored_rx) = tokio::sync::watch::channel(St::Initializing);
        tx.send(St::Available { not_after: 100 }).unwrap();
        let now = 150;
        let mut rx = stored_rx.clone();
        tx.send(St::Available { not_after: 250 }).unwrap(); // lands before the decision
        // Proposed: decide on the value that is marked seen.
        let is_expired = matches!(*rx.borrow_and_update(), St::Available { not_after } if not_after <= now);
        if !is_expired {
            rx.mark_changed();
        }
        assert!(!is_expired);
        let r = tokio::time::timeout(Duration::from_secs(1), rx.changed()).await;
        assert!(matches!(r, Ok(Ok(()))), "fixed pattern: wait() returns at once");
        assert_eq!(*rx.borrow(), St::Available { not_after: 250 });
        // And when it IS expired, the caller waits for the next send, as d5f24b5 intends.
        let mut rx2 = stored_rx.clone();
        let is_expired = matches!(*rx2.borrow_and_update(), St::Available { not_after } if not_after <= 300);
        assert!(is_expired);
        let r = tokio::time::timeout(Duration::from_secs(1), rx2.changed()).await;
        assert!(r.is_err());
        tx.send(St::Available { not_after: 400 }).unwrap();
        assert!(rx2.changed().await.is_ok());
        assert_eq!(*rx2.borrow(), St::Available { not_after: 400 });
    }

    // --- time.rs (verbatim copy) semantics under paused time ---------------------------------

    #[tokio::test(start_paused = true)]
    async fn wallclock_tracks_tokio_time_and_step() {
        let clock = WallClock::simulated(Converter::new());
        let t0 = clock.now(); // advance 0: tokio now (base) < Converter.now -> checked_sub branch, no panic
        tokio::time::sleep(Duration::from_secs(10)).await;
        let t1 = clock.now();
        let d = t1.duration_since(t0).unwrap();
        assert!(d >= Duration::from_secs(10) && d < Duration::from_secs(10) + Duration::from_millis(5), "{d:?}");
        clock.step_forward(Duration::from_secs(200));
        let t2 = clock.now();
        assert_eq!(t2.duration_since(t1).unwrap(), Duration::from_secs(200));
        // instant_at: past -> now; future -> now + d; after a step the mapping follows the wall clock.
        let now = Instant::now();
        assert_eq!(clock.instant_at(t2 - Duration::from_secs(1)), Some(now));
        assert_eq!(clock.instant_at(t2 + Duration::from_secs(7)), Some(now + Duration::from_secs(7)));
        // A due time that was 50 s ahead before the step is now 150 s in the past -> now.
        assert_eq!(clock.instant_at(t1 + Duration::from_secs(50)), Some(now));
    }

    // --- claim 4: skew arithmetic -----------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn skew_arithmetic_forward_backward_huge() {
        let i0 = Instant::now();
        let w0 = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        // no jump
        let (s, j) = skew((i0, w0), (i0 + Duration::from_secs(5), w0 + Duration::from_secs(5)));
        assert_eq!((s, j), (0, Duration::ZERO));
        // forward 95.77 h with 5 s monotonic
        let h = Duration::from_secs_f64(95.77 * 3600.0);
        let (s, j) = skew((i0, w0), (i0 + Duration::from_secs(5), w0 + Duration::from_secs(5) + h));
        assert!(s > 0);
        assert_eq!(j, h);
        // backward step: wall went back 30 s while monotonic advanced 5 s
        let (s, j) = skew((i0, w0), (i0 + Duration::from_secs(5), w0 - Duration::from_secs(25)));
        assert_eq!(s, -(30i128 * 1_000_000_000));
        assert_eq!(j, Duration::from_secs(30));
        // monotonic sample older than previous (cannot happen, but saturates to 0)
        let (s, _) = skew((i0 + Duration::from_secs(5), w0), (i0, w0));
        assert_eq!(s, 0);
        // huge: 1000 years of wall jump -> jump saturates at u64::MAX nanos, no panic
        let (s, j) = skew((i0, w0), (i0, w0 + Duration::from_secs(1000 * 365 * 86400)));
        assert!(s > 0);
        assert_eq!(j, Duration::from_nanos(u64::MAX));
    }

    // --- claim 1 / claim 5: the model of test_refresh_follows_wall_clock_jump --------------

    #[tokio::test(start_paused = true)]
    async fn model_refresh_follows_wall_clock_jump() {
        let start = Instant::now();
        let (clock, tx, log, h) = setup();
        tx.send(Request::Fetch("k".into(), Priority::RealTime)).await.unwrap();
        // first fetch completes at 1 s
        tokio::time::sleep(SEC + Duration::from_millis(1)).await;
        assert_eq!(log.lock().unwrap().len(), 1);
        let issue0 = log.lock().unwrap()[0].issued_wall;

        clock.step_forward(4 * CERT_HALFLIFE);
        tokio::time::sleep(CLOCK_CHECK_INTERVAL + 2 * SEC).await;
        let l = log.lock().unwrap();
        assert_eq!(l.len(), 2, "refresh did not run within CLOCK_CHECK_INTERVAL + 2 s after the jump");
        let popped = l[1].popped_at.duration_since(start);
        eprintln!("refresh popped at t={popped:?} (monotonic since start); issued wall +{:?}", l[1].issued_wall.duration_since(issue0).unwrap());
        assert!(popped <= CLOCK_CHECK_INTERVAL + SEC, "{popped:?}");
        assert!(popped < CERT_HALFLIFE);
        drop(l);
        drop(tx);
        h.await.unwrap();
    }

    // Behaviour preservation (claim 2): without a step, the refresh runs at the half-life.
    #[tokio::test(start_paused = true)]
    async fn model_no_jump_refresh_at_halflife() {
        let start = Instant::now();
        let (_clock, tx, log, h) = setup();
        tx.send(Request::Fetch("k".into(), Priority::RealTime)).await.unwrap();
        tokio::time::sleep(CERT_HALFLIFE + SEC - Duration::from_millis(1)).await;
        assert_eq!(log.lock().unwrap().len(), 1, "no refresh before the half-life");
        tokio::time::sleep(Duration::from_millis(2) + SEC).await;
        let l = log.lock().unwrap();
        assert_eq!(l.len(), 2);
        let popped = l[1].popped_at.duration_since(start);
        eprintln!("no-jump refresh popped at t={popped:?}");
        // issued at 1 s, half-life 50 s -> pop at 51 s (within timer granularity)
        assert!(popped >= SEC + CERT_HALFLIFE - Duration::from_millis(2) && popped <= SEC + CERT_HALFLIFE + Duration::from_millis(2), "{popped:?}");
        drop(l);
        drop(tx);
        h.await.unwrap();
    }

    // A jump while a fetch is in flight: the result is scheduled from the post-jump wall clock.
    #[tokio::test(start_paused = true)]
    async fn model_jump_during_inflight_fetch() {
        let start = Instant::now();
        let (clock, tx, log, h) = setup();
        tx.send(Request::Fetch("k".into(), Priority::RealTime)).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await; // fetch in flight (completes at 1 s)
        clock.step_forward(4 * CERT_HALFLIFE);
        tokio::time::sleep(Duration::from_millis(600)).await; // result processed at ~1 s
        assert_eq!(log.lock().unwrap().len(), 1);
        // Issued (wall) after the jump, half-life 50 s ahead -> refresh at ~51 s monotonic, not now.
        tokio::time::sleep(CLOCK_CHECK_INTERVAL + 2 * SEC).await;
        assert_eq!(log.lock().unwrap().len(), 1, "a fresh post-jump certificate must not be refetched at once");
        tokio::time::sleep(CERT_HALFLIFE).await;
        let l = log.lock().unwrap();
        assert_eq!(l.len(), 2);
        eprintln!("inflight case: refresh popped at t={:?}", l[1].popped_at.duration_since(start));
        drop(l);
        drop(tx);
        h.await.unwrap();
    }

    // An item raised to RealTime while a stale Background schedule exists runs at once and the
    // jump branch does not touch it (claim 1, "priority raised" path).
    #[tokio::test(start_paused = true)]
    async fn model_realtime_bump_runs_now() {
        let start = Instant::now();
        let (_clock, tx, log, h) = setup();
        tx.send(Request::Fetch("k".into(), Priority::RealTime)).await.unwrap();
        tokio::time::sleep(SEC + Duration::from_millis(1)).await;
        tx.send(Request::Fetch("k".into(), Priority::RealTime)).await.unwrap();
        tokio::time::sleep(SEC + Duration::from_millis(1)).await;
        let l = log.lock().unwrap();
        assert_eq!(l.len(), 2);
        eprintln!("bump: second pop at t={:?}", l[1].popped_at.duration_since(start));
        assert!(l[1].popped_at.duration_since(start) < SEC + Duration::from_millis(5));
        drop(l);
        drop(tx);
        h.await.unwrap();
    }
}
