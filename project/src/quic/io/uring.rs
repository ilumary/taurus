use std::{
    cell::UnsafeCell,
    cell::{Cell, RefCell},
    collections::VecDeque,
    io,
    net::SocketAddr,
    os::unix::io::{AsRawFd, RawFd},
    rc::Rc,
    time::Instant,
};

use crate::io::{
    addr_to_storage, bind_reuseport,
    buffer::{RecvBuf, RecvPool, SendBatch, SendPool},
    ecn_from_control, storage_to_addr, BatchConfig, Capabilities, CmsgBuf, CrossThreadWaker,
    MAX_GSO_BYTES, MAX_GSO_SEGMENTS,
};

use io_uring::{opcode, types, IoUring};

/// user data msb indicates wether completion queue event was a send or read op
const SEND_BIT: u64 = 1 << 63;

/// everything else is the index into the buffer pool
const IDX_MASK: u64 = !SEND_BIT;

/// set only for the eventfd read completion. safe because encoded index < u32::MAX
const WAKER_UD: u64 = u64::MAX;

/// single recv operation storage
#[repr(C)]
struct RecvOp {
    msghdr: libc::msghdr,
    iov: libc::iovec,
    name: libc::sockaddr_storage,
    control: CmsgBuf,
}

/// single send operation storage, keyed by send descriptor. needs to also keep msghdr, iov, and
/// control fields in contrast to polling backend as uring is not synchronous and the data needs to
/// be available after the submission
#[repr(C)]
struct SendOp {
    msghdr: libc::msghdr,
    iov: libc::iovec,
    name: libc::sockaddr_storage,
    namelen: libc::socklen_t,
    control: CmsgBuf,

    /// GSO segment size, 0 for a single datagram
    seg: u32,
}

pub struct Io {
    ring: RefCell<IoUring>,
    socket: socket2::Socket,
    sock_fd: RawFd,

    /// ring buffer holding configured recv slots, each with configured size
    recv_pool: Rc<RecvPool>,

    /// ring buffer holding configured send slots, each with configured size. if gso is enabled each
    /// slot has max ip datagram size to support batch polling
    send_pool: Rc<SendPool>,

    /// pre-allocated buffer holding one [`RecvOp`] per recv slot in recv_pool
    recv_ops: Box<[UnsafeCell<RecvOp>]>,

    /// pre-allocated buffer holding one [`SendOp`] per send slot in send_pool
    send_ops: Box<[UnsafeCell<SendOp>]>,
    pending_send: RefCell<VecDeque<u32>>,

    /// ops submitted to the kernel that have not yet yielded a CQE
    inflight: Cell<u32>,

    /// wether gso is enabled
    gso_enabled: bool,

    /// if gro is enabled, will be checked in bind() via setsockopt call
    gro_enabled: bool,

    /// cross thread waker backed by eventfd as this module is linux only
    waker: CrossThreadWaker,

    /// 8-byte sink for the waker read which is a eventfd counter. raw pointer so it isnt freed on
    /// drop as kernel may still have active read against this address, so its leaked
    waker_buf: *mut u8,

    /// if there is an active read call in the uring submission queue
    waker_armed: Cell<bool>,
}

impl Io {
    pub fn bind(
        addr: SocketAddr,
        config: &BatchConfig,
        waker: CrossThreadWaker,
    ) -> io::Result<Self> {
        let config = *config;
        assert!(
            !config.gro || config.recv_buf_size >= MAX_GSO_BYTES,
            "gro needs buf_size >= 65535 or coalesced datagrams truncate"
        );
        let socket = bind_reuseport(addr)?;
        let sock_fd = socket.as_raw_fd();

        // the ring has to hold at least one maximum-size batch or a full batch can never be
        // packed
        // TODO figure out an general, more elegant way to handle ceiling and constraints in
        // configured buffer sizes
        let max_batch = if config.gso {
            MAX_GSO_BYTES
        } else {
            config.recv_buf_size
        };
        assert!(
            config.send_ring >= max_batch,
            "send_ring must hold at least one maximum-size batch"
        );

        let mut gro_enabled = false;
        if config.gro {
            let on: libc::c_int = 1;
            let rc = unsafe {
                libc::setsockopt(
                    sock_fd,
                    libc::SOL_UDP,
                    libc::UDP_GRO,
                    &on as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };

            gro_enabled = rc == 0;
            if !gro_enabled {
                tracing::warn!(error = %io::Error::last_os_error(), "kernel refused gro");
            }
        }

        let entries = (config.recv_slots + config.send_slots + 1).next_power_of_two() as u32;
        let ring = IoUring::new(entries.max(8))?;

        let recv_pool = RecvPool::new(config.recv_slots, config.recv_buf_size);
        let send_pool = SendPool::new(config.send_ring, config.send_slots);

        let recv_ops = (0..config.recv_slots)
            .map(|_| UnsafeCell::new(unsafe { std::mem::zeroed::<RecvOp>() }))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        let send_ops = (0..config.send_slots)
            .map(|_| UnsafeCell::new(unsafe { std::mem::zeroed::<SendOp>() }))
            .collect::<Vec<_>>()
            .into_boxed_slice();

        tracing::info!(address = %addr, "successfully initialized io_uring");

        Ok(Self {
            ring: RefCell::new(ring),
            socket,
            sock_fd,
            recv_pool,
            send_pool,
            recv_ops,
            send_ops,
            pending_send: RefCell::new(VecDeque::with_capacity(config.send_slots)),
            inflight: Cell::new(0),
            gso_enabled: config.gso,
            gro_enabled,
            waker,
            waker_buf: Box::into_raw(Box::new([0u8; 8])) as *mut u8,
            waker_armed: Cell::new(false),
        })
    }

    #[inline]
    fn recv_msghdr_ptr(&self, idx: u32) -> *mut libc::msghdr {
        unsafe { std::ptr::addr_of_mut!((*self.recv_ops[idx as usize].get()).msghdr) }
    }

    #[inline]
    fn send_msghdr_ptr(&self, desc: u32) -> *const libc::msghdr {
        unsafe { std::ptr::addr_of!((*self.send_ops[desc as usize].get()).msghdr) }
    }

    /// init a receive op msghdr to point at its pool buffer
    unsafe fn prep_recv(&self, idx: u32) {
        let op = &mut *self.recv_ops[idx as usize].get();
        op.name = std::mem::zeroed();
        op.iov.iov_base = self.recv_pool.ptr(idx) as *mut libc::c_void;
        op.iov.iov_len = self.recv_pool.slot_size();
        op.msghdr = std::mem::zeroed();
        op.msghdr.msg_name = std::ptr::addr_of_mut!(op.name) as *mut libc::c_void;
        op.msghdr.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        op.msghdr.msg_iov = std::ptr::addr_of_mut!(op.iov);
        op.msghdr.msg_iovlen = 1 as _;
        op.msghdr.msg_control = op.control.0.as_mut_ptr() as *mut libc::c_void;
        op.msghdr.msg_controllen = op.control.0.len() as _;
    }

    /// read back source address, gro segment size, and ecn after a recv
    unsafe fn parse_recv(&self, idx: u32) -> (SocketAddr, Option<usize>, u8) {
        let op = &*self.recv_ops[idx as usize].get();
        let src = storage_to_addr(&op.name, op.msghdr.msg_namelen)
            .unwrap_or_else(|| SocketAddr::from(([0u8, 0, 0, 0], 0)));

        let seg = if self.gro_enabled && op.msghdr.msg_controllen != 0 {
            parse_gro(std::ptr::addr_of!(op.msghdr))
        } else {
            None
        };

        let ecn = ecn_from_control(op.msghdr.msg_control, op.msghdr.msg_controllen as usize);
        (src, seg, ecn)
    }

    /// build a send op's msghdr
    unsafe fn prep_send(&self, desc: u32) {
        let op = &mut *self.send_ops[desc as usize].get();
        let bytes = self.send_pool.bytes(desc);

        op.iov.iov_base = bytes.as_ptr() as *mut libc::c_void;
        op.iov.iov_len = bytes.len();
        op.msghdr = std::mem::zeroed();
        op.msghdr.msg_name = std::ptr::addr_of_mut!(op.name) as *mut libc::c_void;
        op.msghdr.msg_namelen = op.namelen;
        op.msghdr.msg_iov = std::ptr::addr_of_mut!(op.iov);
        op.msghdr.msg_iovlen = 1 as _;

        if op.seg > 0 {
            op.msghdr.msg_control = op.control.0.as_mut_ptr() as *mut libc::c_void;
            op.msghdr.msg_controllen =
                libc::CMSG_SPACE(std::mem::size_of::<u16>() as libc::c_uint) as _;
            let cmsg = libc::CMSG_FIRSTHDR(std::ptr::addr_of!(op.msghdr));
            (*cmsg).cmsg_level = libc::SOL_UDP;
            (*cmsg).cmsg_type = libc::UDP_SEGMENT;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as libc::c_uint) as _;
            let data = libc::CMSG_DATA(cmsg) as *mut u16;
            data.write_unaligned(op.seg as u16);
        } else {
            op.msghdr.msg_control = std::ptr::null_mut();
            op.msghdr.msg_controllen = 0 as _;
        }
    }

    /// arm the cross-thread waker as a read of the eventfd counter. idempotent while armed. The
    /// completed read both wakes the wait and drains the eventfd in one step
    fn arm_waker(&self) {
        if self.waker_armed.get() {
            return;
        }

        let mut ring = self.ring.borrow_mut();
        let mut sq = ring.submission();
        let entry = opcode::Read::new(types::Fd(self.waker.read_fd()), self.waker_buf, 8)
            .build()
            .user_data(WAKER_UD);

        // SAFETY: `waker_buf` is a stable heap allocation
        if unsafe { sq.push(&entry) }.is_ok() {
            self.waker_armed.set(true);
            self.inflight.set(self.inflight.get() + 1);
        }
    }

    /// push receive SQEs for every free buffer. returns the number queued
    fn fill_recv_sqes(&self) -> usize {
        let mut ring = self.ring.borrow_mut();
        let mut posted = 0usize;
        let mut sq = ring.submission();

        loop {
            if sq.is_full() {
                break;
            }

            let idx = match self.recv_pool.alloc() {
                Some(i) => i,
                None => break,
            };

            // SAFETY: idx is a freshly allocated free slot
            unsafe { self.prep_recv(idx) };
            let entry = opcode::RecvMsg::new(types::Fd(self.sock_fd), self.recv_msghdr_ptr(idx))
                .build()
                .user_data(idx as u64);

            // SAFETY: the op's msghdr/iov/buffer live in `recv_ops`/pool and are not touched until
            // the matching completion is processed
            if unsafe { sq.push(&entry) }.is_err() {
                self.recv_pool.free(idx);
                break;
            }
            posted += 1;
        }

        self.inflight.set(self.inflight.get() + posted as u32);
        posted
    }

    /// push send SQEs for everything queued. returns the number queued
    fn fill_send_sqes(&self) -> usize {
        let mut ring = self.ring.borrow_mut();
        let mut pending = self.pending_send.borrow_mut();
        let mut posted = 0usize;
        let mut sq = ring.submission();

        while let Some(&desc) = pending.front() {
            if sq.is_full() {
                break;
            }

            // SAFETY: desc is an enqueued batch with valid stored metadata
            unsafe { self.prep_send(desc) };
            let entry = opcode::SendMsg::new(types::Fd(self.sock_fd), self.send_msghdr_ptr(desc))
                .build()
                .user_data(desc as u64 | SEND_BIT);

            // SAFETY: msghdr/iov/region live in `send_ops`/pool until reaped
            if unsafe { sq.push(&entry) }.is_err() {
                break;
            }

            pending.pop_front();
            posted += 1;
        }

        self.inflight.set(self.inflight.get() + posted as u32);
        posted
    }

    /// block until at least one completion is ready, or the specifiec deadline passes, using
    /// io_uring's own wait timeout. returns `true` if the wait timed out. submits any queued
    /// SQEs as part of the same syscall
    fn wait_native(&self, deadline: Option<Instant>) -> io::Result<bool> {
        let ring = self.ring.borrow();
        let submitter = ring.submitter();

        match deadline {
            Some(at) => {
                let dur = at.saturating_duration_since(Instant::now());
                let ts = types::Timespec::from(dur);
                let args = types::SubmitArgs::new().timespec(&ts);

                match submitter.submit_with_args(1, &args) {
                    Ok(_) => Ok(false),
                    Err(ref e) if e.raw_os_error() == Some(libc::ETIME) => Ok(true),
                    Err(ref e) if e.kind() == io::ErrorKind::Interrupted => Ok(false),
                    Err(e) => Err(e),
                }
            }
            None => match submitter.submit_and_wait(1) {
                Ok(_) => Ok(false),
                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => Ok(false),
                Err(e) => Err(e),
            },
        }
    }

    /// drains all available completions
    fn reap(&self, out: &mut Vec<RecvBuf>) -> usize {
        let mut ring = self.ring.borrow_mut();
        let mut produced = 0usize;

        loop {
            let mut progressed = false;
            {
                let cq = ring.completion();
                for cqe in cq {
                    progressed = true;
                    self.inflight.set(self.inflight.get().saturating_sub(1));
                    let ud = cqe.user_data();
                    if ud == WAKER_UD {
                        self.waker_armed.set(false);
                        continue;
                    }

                    let res = cqe.result();
                    if ud & SEND_BIT != 0 {
                        if res < 0 {
                            if -res != libc::ECANCELED {
                                tracing::warn!(
                                    error = %io::Error::from_raw_os_error(-res),
                                    "send failed, dropping datagram"
                                );
                            }
                        } else {
                            tracing::trace!(bytes = res, "send completed");
                        }
                        self.send_pool.reclaim((ud & IDX_MASK) as u32);
                        continue;
                    }

                    let idx = ud as u32;
                    if res < 0 {
                        if -res != libc::ECANCELED {
                            tracing::debug!(error = %io::Error::from_raw_os_error(-res), "recv failed");
                        }
                        self.recv_pool.free(idx);
                        continue;
                    }

                    // SAFETY: completion implies the kernel finished this slot
                    let (src, seg, ecn) = unsafe { self.parse_recv(idx) };
                    out.push(self.recv_pool.buf(idx, res as usize, src, seg, ecn));
                    produced += 1;
                }
            }

            if !progressed {
                break;
            }
        }
        produced
    }

    /// open a send batch whose segments are up to `seg` bytes. returns `None` under backpressure
    pub fn begin(&self, seg: usize) -> Option<SendBatch<'_>> {
        let max_bytes = if self.gso_enabled {
            (seg * MAX_GSO_SEGMENTS).min(MAX_GSO_BYTES)
        } else {
            seg
        };
        self.send_pool.begin(seg, max_bytes)
    }

    /// queue a filled batch for transmission to `dest`. `seg` is the segment size
    pub fn enqueue(&self, batch: SendBatch<'_>, dest: SocketAddr, seg: usize) {
        let gso = self.gso_enabled && batch.count() > 1;
        let desc = batch.finish();

        // SAFETY: desc is freshly published. no in-flight op references it yet
        unsafe {
            let op = &mut *self.send_ops[desc as usize].get();
            op.name = std::mem::zeroed();
            op.namelen = addr_to_storage(dest, &mut op.name);
            op.seg = if gso { seg as u32 } else { 0 };
        }
        self.pending_send.borrow_mut().push_back(desc);
    }

    /// block until >=1 datagram is readable, the waker fires, or `deadline` is reached. received
    /// datagrams are appended to `out`. returns the count read
    pub fn poll(&self, out: &mut Vec<RecvBuf>, deadline: Option<Instant>) -> io::Result<usize> {
        self.arm_waker();
        self.fill_recv_sqes();
        let _timed_out = self.wait_native(deadline)?; //TODO handle timeout
        Ok(self.reap(out))
    }

    /// submit all queued sends
    pub fn flush(&self) -> io::Result<()> {
        let n = self.fill_send_sqes();
        if n > 0 {
            tracing::trace!(batches = n, "submitting sends");
            if let Err(e) = self.ring.borrow().submit() {
                tracing::error!(error = %e, "io_uring submit failed");
                return Err(e);
            }
        }
        Ok(())
    }

    /// intentionally leaks internal buffer pools and ops arrays
    fn leak_kernel_referenced(&mut self) {
        std::mem::forget(self.recv_pool.clone());
        std::mem::forget(self.send_pool.clone());

        let recv_ops = std::mem::replace(&mut self.recv_ops, Box::new([]));
        let send_ops = std::mem::replace(&mut self.send_ops, Box::new([]));

        Box::leak(recv_ops);
        Box::leak(send_ops);
    }

    pub fn waker(&self) -> CrossThreadWaker {
        self.waker.clone()
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket
            .local_addr()?
            .as_socket()
            .ok_or_else(|| io::Error::other("non-IP local addr"))
    }

    pub fn capabilities(&self) -> Capabilities {
        Capabilities {
            backend: "io_uring",
            gso: self.gso_enabled,
            gro: self.gro_enabled,
        }
    }
}

unsafe fn parse_gro(msg: *const libc::msghdr) -> Option<usize> {
    let mut cmsg = libc::CMSG_FIRSTHDR(msg);
    while !cmsg.is_null() {
        if (*cmsg).cmsg_level == libc::SOL_UDP && (*cmsg).cmsg_type == libc::UDP_GRO {
            let data = libc::CMSG_DATA(cmsg) as *const libc::c_int;
            return Some(data.read_unaligned() as usize);
        }
        cmsg = libc::CMSG_NXTHDR(msg, cmsg);
    }
    None
}

impl Drop for Io {
    fn drop(&mut self) {
        if self.inflight.get() == 0 {
            unsafe { drop(Box::from_raw(self.waker_buf as *mut [u8; 8])) };
            return;
        }

        if std::thread::panicking() {
            self.leak_kernel_referenced();
            return;
        }

        let timeout = types::Timespec::from(std::time::Duration::from_secs(2));
        let cancelled = {
            let ring = self.ring.get_mut();
            ring.submitter()
                .register_sync_cancel(Some(timeout), types::CancelBuilder::any())
        };

        match cancelled {
            Ok(()) => {
                let mut drain = Vec::new();
                let _ = self.reap(&mut drain);
                unsafe { drop(Box::from_raw(self.waker_buf as *mut [u8; 8])) };
            }
            Err(_) => {
                self.leak_kernel_referenced();
            }
        }
    }
}
