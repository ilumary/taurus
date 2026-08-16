use std::{
    cell::Cell,
    future::Future,
    io,
    marker::PhantomData,
    pin::Pin,
    rc::Rc,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use async_task::{Runnable, Task};
use crossbeam_channel::{Receiver, Sender};

use crate::io::CrossThreadWaker;

/// max tasks run per loop turn, bounds how long app code can delay socket polling
pub const TASK_BUDGET: usize = 64;

/// thread local executor
pub struct LocalExec {
    tx: Sender<Runnable>,
    rx: Receiver<Runnable>,

    /// the shard's park flag, shared with its mailbox
    parked: Arc<AtomicBool>,
    waker: CrossThreadWaker,

    /// tasks polled since the last reset, for the slow-turn watchdog
    ran: Cell<usize>,

    /// makes this struct !Send and !Sync
    _not_send: PhantomData<Rc<()>>,
}

impl LocalExec {
    pub fn new(parked: Arc<AtomicBool>, waker: CrossThreadWaker) -> Self {
        let (tx, rx) = crossbeam_channel::unbounded();
        Self {
            tx,
            rx,
            parked,
            waker,
            ran: Cell::new(0),
            _not_send: PhantomData,
        }
    }

    /// spawn a `!Send` future onto this shard. the returned handle cancels the
    /// task when dropped
    pub fn spawn<F>(&self, fut: F) -> Task<F::Output>
    where
        F: Future + 'static,
        F::Output: 'static,
    {
        let tx = self.tx.clone();
        let parked = self.parked.clone();
        let waker = self.waker.clone();

        // called from any thread when the task is woken, must not run the task.
        // while the shard is running the swap sees false and no syscall is issued
        let schedule = move |runnable| {
            let _ = tx.send(runnable);
            if parked.swap(false, Ordering::SeqCst) {
                waker.wake();
            }
        };

        let (runnable, task) = async_task::spawn_local(fut, schedule);
        runnable.schedule();
        task
    }

    /// poll the tasks that are ready now, up to `budget`, returns how many ran
    pub fn drain(&self, budget: usize) -> usize {
        let mut left = self.rx.len().min(budget);
        let mut ran = 0;

        while left > 0 {
            let Ok(runnable) = self.rx.try_recv() else {
                break;
            };

            runnable.run();
            ran += 1;
            left -= 1;
        }

        self.ran.set(self.ran.get() + ran);
        if ran > 0 {
            tracing::trace!(tasks = ran, "ran tasks");
        }
        ran
    }

    /// true when no task is ready. the loop must not park while this is false or
    /// ready tasks sit until the next packet arrives
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.rx.is_empty()
    }

    /// tasks polled since the last call, for the watchdog
    #[inline]
    pub fn take_ran(&self) -> usize {
        self.ran.replace(0)
    }
}

/// poll a join handle without registering a waker. the task itself is driven by
/// [`LocalExec::drain`], this only checks whether the output is ready, so nothing
/// ever needs waking through this context
pub fn try_join<T>(task: &mut Task<T>) -> Option<T> {
    match Pin::new(task).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(out) => Some(out),
        Poll::Pending => None,
    }
}

/// bind the calling thread to `core`. linux only
pub fn pin_to_core(core: usize) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        unsafe {
            let mut set: libc::cpu_set_t = std::mem::zeroed();
            libc::CPU_ZERO(&mut set);
            libc::CPU_SET(core, &mut set);
            if libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = core;
        Ok(())
    }
}

const WARN_INTERVAL: Duration = Duration::from_secs(1);

/// flags turns that overran, indicating a handoff to [`Offload`] may be better. the contract cannot be
/// enforced by the type system, so it is enforced by complaining loudly
pub struct Watchdog {
    /// time duration
    limit: Duration,

    /// timepoint of last warning that was emitted
    last_warn: Option<Instant>,

    /// overruns since the last warning was emitted
    overruns: u64,

    /// worst duration
    worst: Duration,
}

impl Watchdog {
    pub fn new(limit: Duration) -> Self {
        Self {
            limit,
            last_warn: None,
            overruns: 0,
            worst: Duration::ZERO,
        }
    }

    pub fn turn(&mut self, began: Instant, exec: &LocalExec) {
        let took = began.elapsed();
        let ran = exec.take_ran();

        if took <= self.limit {
            return;
        }

        self.overruns += 1;
        self.worst = self.worst.max(took);

        let now = Instant::now();
        if self.last_warn.is_some_and(|t| now - t < WARN_INTERVAL) {
            return;
        }
        self.last_warn = Some(now);

        tracing::warn!(
            took_us = took.as_micros(),
            worst_us = self.worst.as_micros(),
            limit_us = self.limit.as_micros(),
            tasks = ran,
            overruns = self.overruns,
            "shard turn overran"
        );

        self.overruns = 0;
        self.worst = Duration::ZERO;
    }
}

/// tokio pool for work that must not run on a shard. sits on cores the shards do
/// not use, so a slow query never competes with packet processing. one pool is
/// shared by every shard and reached from a handler through `conn.offload`
pub struct Offload {
    /// tokio runtime, may extend this to accept other runtimes/models
    rt: tokio::runtime::Runtime,
}

impl Offload {
    pub fn new(worker_threads: usize, cores: &[usize]) -> io::Result<Self> {
        let mut builder = tokio::runtime::Builder::new_multi_thread();
        builder.worker_threads(worker_threads.max(1)).enable_all();

        if !cores.is_empty() {
            let cores = cores.to_vec();
            let next = Arc::new(AtomicUsize::new(0));
            builder.on_thread_start(move || {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let _ = pin_to_core(cores[i % cores.len()]);
            });
        }

        tracing::debug!(threads = worker_threads.max(1), cores = ?cores, "offload pool started");

        Ok(Self {
            rt: builder.build()?,
        })
    }

    /// run a `Send` future on the pool and await its output from a shard task
    pub async fn run<F>(&self, fut: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.rt.spawn(async move {
            let _ = tx.send(fut.await);
        });
        rx.await.expect("offloaded task panicked")
    }

    /// run blocking work on the pool and await its result from a shard task
    pub async fn blocking<T, F>(&self, f: F) -> T
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.rt.spawn_blocking(move || {
            let _ = tx.send(f());
        });
        rx.await.expect("blocking task panicked")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::rc::Rc;
    use std::time::Duration;

    fn get_local_executor() -> (LocalExec, Arc<AtomicBool>) {
        let parked = Arc::new(AtomicBool::new(false));
        let waker = CrossThreadWaker::new().unwrap();
        let exec = LocalExec::new(parked.clone(), waker);
        (exec, parked)
    }

    fn run_until<T>(exec: &LocalExec, task: &mut Task<T>) -> T {
        loop {
            exec.drain(TASK_BUDGET);
            if let Some(out) = try_join(task) {
                return out;
            }
            while exec.is_empty() {
                std::hint::spin_loop();
            }
        }
    }

    /// reschedule once, so a task is polled twice
    async fn yield_now() {
        struct YieldOnce(bool);
        impl Future for YieldOnce {
            type Output = ();
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                if self.0 {
                    return Poll::Ready(());
                }
                self.0 = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
        YieldOnce(false).await
    }

    #[test]
    fn spawn_drain_budget_and_not_send() {
        let (exec, _parked) = get_local_executor();

        // a !Send future: an Rc is held across an await, which tokio would reject
        let log = Rc::new(Cell::new(0usize));
        let l = log.clone();
        let mut root = exec.spawn(async move {
            l.set(l.get() + 1);
            yield_now().await;
            l.set(l.get() + 10);
            l.get()
        });

        assert_eq!(log.get(), 0);
        assert!(!exec.is_empty());

        assert_eq!(exec.drain(TASK_BUDGET), 1);
        assert_eq!(log.get(), 1);
        assert!(try_join(&mut root).is_none());

        assert_eq!(exec.drain(TASK_BUDGET), 1);
        assert_eq!(try_join(&mut root), Some(11));
        assert!(exec.is_empty());
        assert_eq!(exec.take_ran(), 2);

        let hits = Rc::new(Cell::new(0usize));
        let tasks: Vec<Task<()>> = (0..5)
            .map(|_| {
                let h = hits.clone();
                exec.spawn(async move { h.set(h.get() + 1) })
            })
            .collect();

        assert_eq!(exec.drain(2), 2);
        assert_eq!(hits.get(), 2);
        assert!(!exec.is_empty());
        assert_eq!(exec.drain(TASK_BUDGET), 3);
        assert_eq!(hits.get(), 5);
        assert!(exec.is_empty());
        tasks.into_iter().for_each(|t| t.detach());
    }

    #[test]
    fn cross_thread_wake_pokes_the_waker_only_when_parked() {
        let (exec, parked) = get_local_executor();

        let (tx, rx) = tokio::sync::oneshot::channel::<u32>();
        let mut root = exec.spawn(async move { rx.await.unwrap() });

        assert_eq!(exec.drain(TASK_BUDGET), 1);
        assert!(exec.is_empty());
        assert!(try_join(&mut root).is_none());

        parked.store(true, Ordering::SeqCst);

        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(10));
            tx.send(42).unwrap();
        });

        while parked.load(Ordering::SeqCst) {
            std::hint::spin_loop();
        }
        assert!(!exec.is_empty());

        assert_eq!(run_until(&exec, &mut root), 42);

        let (tx2, rx2) = tokio::sync::oneshot::channel::<u32>();
        let mut t2 = exec.spawn(async move { rx2.await.unwrap() });
        exec.drain(TASK_BUDGET);
        assert!(!parked.load(Ordering::SeqCst));
        tx2.send(7).unwrap();
        assert!(!parked.load(Ordering::SeqCst),);
        assert_eq!(run_until(&exec, &mut t2), 7);
    }

    #[test]
    fn dropping_the_handle_cancels_the_task() {
        let (exec, _parked) = get_local_executor();

        let ran = Rc::new(Cell::new(false));
        let r = ran.clone();
        let task = exec.spawn(async move {
            yield_now().await;
            r.set(true);
        });

        assert_eq!(exec.drain(TASK_BUDGET), 1);
        drop(task);

        exec.drain(TASK_BUDGET);
        assert!(!ran.get());
        assert!(exec.is_empty());
    }

    #[test]
    fn offload_runs_foreign_work_off_the_shard() {
        let (exec, _parked) = get_local_executor();
        let pool = Rc::new(Offload::new(2, &[]).unwrap());

        let shard_thread = std::thread::current().id();
        let p = pool.clone();

        // a !Send handler awaiting some external work
        let local = Rc::new(Cell::new(0u32));
        let l = local.clone();
        let mut root = exec.spawn(async move {
            let remote = p
                .run(async {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    (21u32, std::thread::current().id())
                })
                .await;

            let blocking = p.blocking(|| 2u32).await;

            l.set(remote.0 * blocking); // back on the shard, touching !Send state
            (l.get(), remote.1)
        });

        let (value, worker) = run_until(&exec, &mut root);
        assert_eq!(value, 42);
        assert_eq!(local.get(), 42);
        assert_ne!(worker, shard_thread,);
    }

    #[test]
    fn watchdog_flags_blocking_handlers() {
        let (exec, _parked) = get_local_executor();
        let mut dog = Watchdog::new(Duration::from_millis(5));

        let began = Instant::now();
        exec.spawn(async {}).detach();
        exec.drain(TASK_BUDGET);
        dog.turn(began, &exec);
        assert_eq!(dog.overruns, 0);
        assert_eq!(exec.take_ran(), 0);

        let began = Instant::now();
        exec.spawn(async { std::thread::sleep(Duration::from_millis(8)) })
            .detach();
        exec.drain(TASK_BUDGET);
        dog.turn(began, &exec);
        assert!(dog.last_warn.is_some());
        assert_eq!(dog.overruns, 0);

        for _ in 0..3 {
            let began = Instant::now();
            std::thread::sleep(Duration::from_millis(6));
            dog.turn(began, &exec);
        }
        assert_eq!(dog.overruns, 3);
        assert!(dog.worst >= Duration::from_millis(6));
    }
}
