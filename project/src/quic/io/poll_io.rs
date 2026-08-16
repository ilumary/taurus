use super::*;

use std::{cell::UnsafeCell, collections::VecDeque, os::unix::io::AsRawFd};

use crate::io::buffer::{RecvBuf, RecvPool, SendBatch, SendPool};

// macOS and iOS private SPI for batched receive. not in `libc`
#[cfg(any(target_os = "macos", target_os = "ios"))]
mod darwin {
    #[repr(C)]
    pub struct MsgHdrX {
        pub hdr: libc::msghdr,
        pub datalen: libc::size_t,
    }

    extern "C" {
        pub fn sendmsg_x(
            s: libc::c_int,
            msgp: *const MsgHdrX,
            cnt: libc::c_uint,
            flags: libc::c_int,
        ) -> libc::ssize_t;

        pub fn recvmsg_x(
            s: libc::c_int,
            msgp: *mut MsgHdrX,
            cnt: libc::c_uint,
            flags: libc::c_int,
        ) -> libc::ssize_t;
    }
}

/// stored destination/length for an enqueued send
struct SendMeta {
    name: libc::sockaddr_storage,
    namelen: libc::socklen_t,

    /// UDP_SEGMENT size for a GSO batch, 0 for a single datagram (linux only)
    seg: u32,
}

/// generic POSIX io backend based on poll()/ppoll() with specific macOS and iOS fast path
pub struct Io {
    /// socket handle
    socket: socket2::Socket,

    /// receive buffer pool
    recv_pool: Rc<RecvPool>,

    /// send buffer pool
    send_pool: Rc<SendPool>,

    /// metadata for sending
    send_meta: Box<[UnsafeCell<SendMeta>]>,

    /// holds descriptors of batches to be sent
    pending_send: RefCell<VecDeque<u32>>,

    /// count of datagrams that hit a full OS transmit buffer
    tx_blocked: Cell<u64>,

    /// IO config
    config: BatchConfig,

    /// waker
    waker: CrossThreadWaker,

    /// udp segmentation offload set at bind, linux only
    gso_enabled: bool,

    /// udp receive offload set at bind, linux only
    gro_enabled: bool,
}

impl Io {
    pub fn bind(
        addr: SocketAddr,
        config: &BatchConfig,
        waker: CrossThreadWaker,
    ) -> io::Result<Self> {
        let config = *config;
        let socket = bind_reuseport(addr)?;
        let (gso_enabled, gro_enabled) = Self::configure_offload(&socket, &config);
        let recv_pool = RecvPool::new(config.recv_slots, config.recv_buf_size);
        let send_pool = SendPool::new(config.send_ring, config.send_slots);

        let send_meta = (0..config.send_slots)
            .map(|_| {
                UnsafeCell::new(SendMeta {
                    name: unsafe { std::mem::zeroed() },
                    namelen: 0,
                    seg: 0,
                })
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();

        Ok(Self {
            socket,
            recv_pool,
            send_pool,
            send_meta,
            pending_send: RefCell::new(VecDeque::with_capacity(config.send_slots)),
            tx_blocked: Cell::new(0),
            config,
            waker,
            gso_enabled,
            gro_enabled,
        })
    }

    /// enable gso/gro and report what the socket accepted. linux only
    #[cfg(target_os = "linux")]
    fn configure_offload(socket: &socket2::Socket, config: &BatchConfig) -> (bool, bool) {
        assert!(
            !config.gro || config.recv_buf_size >= MAX_GSO_BYTES,
            "gro needs recv_buf_size >= 65535 or coalesced datagrams truncate"
        );

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
                    socket.as_raw_fd(),
                    libc::SOL_UDP,
                    libc::UDP_GRO,
                    &on as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };

            gro_enabled = rc == 0;
            if !gro_enabled {
                tracing::warn!(error = %io::Error::last_os_error(), "kernel refused UDP_GRO");
            }
        }

        (config.gso, gro_enabled)
    }

    #[cfg(not(target_os = "linux"))]
    fn configure_offload(_socket: &socket2::Socket, _config: &BatchConfig) -> (bool, bool) {
        (false, false)
    }

    /// open a send batch of segments up to `seg` bytes. with GSO the batch may pack
    /// several segments the kernel re-cuts, otherwise it is one datagram. `None`
    /// under backpressure
    pub fn begin(&self, seg: usize) -> Option<SendBatch<'_>> {
        let max_bytes = if self.gso_enabled {
            (seg * MAX_GSO_SEGMENTS).min(MAX_GSO_BYTES)
        } else {
            seg
        };
        self.send_pool.begin(seg, max_bytes)
    }

    /// enqueue a filled batch. the udp segment cmsg is attached only when gso is on and
    /// the batch actually holds more than one datagram
    pub fn enqueue(&self, batch: SendBatch<'_>, dest: SocketAddr, seg: usize) {
        let gso = self.gso_enabled && batch.count() > 1;
        let desc = batch.finish();
        unsafe {
            let meta = &mut *self.send_meta[desc as usize].get();
            meta.name = std::mem::zeroed();
            meta.namelen = addr_to_storage(dest, &mut meta.name);
            meta.seg = if gso { seg as u32 } else { 0 };
        }
        self.pending_send.borrow_mut().push_back(desc);
    }

    /// block until >=1 datagram is readable, the waker fires, or deadline is hit,
    /// appending received datagrams to `out`. returns the count read
    pub fn poll(&self, out: &mut Vec<RecvBuf>, deadline: Option<Instant>) -> io::Result<usize> {
        let (produced, _drained) = self.drain_recv(out)?;
        if produced > 0 {
            return Ok(produced);
        }

        let (sock_ready, waker_ready) = self.block_on_fds(deadline)?;
        if waker_ready {
            self.waker.drain();
        }

        if sock_ready {
            let (p, _) = self.drain_recv(out)?;
            tracing::trace!(datagrams = p, "datagrams read");
            return Ok(p);
        }

        Ok(0)
    }

    /// emits all enqueued packets onto the wire. datagrams the OS transmit buffer
    /// refused stay queued and are retried on the next flush
    pub fn flush(&self) -> io::Result<()> {
        self.drain_send()
    }

    /// push refused descriptors back to the front, preserving submission order so
    /// the send pool still reclaims its regions in order
    fn requeue(&self, idxs: &[u32]) {
        let mut q = self.pending_send.borrow_mut();
        for &desc in idxs.iter().rev() {
            q.push_front(desc);
        }
        let total = self.tx_blocked.get() + idxs.len() as u64;
        self.tx_blocked.set(total);
        tracing::debug!(
            deferred = idxs.len(),
            tx_blocked = total,
            "os transmit buffer full, retrying next flush"
        );
    }

    /// linux recvmmsg receive path. returns (produced, drained_to_empty), never
    /// blocks. drained_to_empty means the socket reported no more datagrams
    #[cfg(target_os = "linux")]
    fn drain_recv(&self, out: &mut Vec<RecvBuf>) -> io::Result<(usize, bool)> {
        const BATCH: usize = 64;
        let want = self.config.recv_batch_datagrams.min(BATCH);

        let mut idxs = [u32::MAX; BATCH];
        let mut iovs: [libc::iovec; BATCH] = unsafe { std::mem::zeroed() };
        let mut names: [libc::sockaddr_storage; BATCH] = unsafe { std::mem::zeroed() };
        let mut ctrls: [CmsgBuf; BATCH] = unsafe { std::mem::zeroed() };
        let mut hdrs: [libc::mmsghdr; BATCH] = unsafe { std::mem::zeroed() };

        let mut n = 0usize;
        while n < want {
            let idx = match self.recv_pool.alloc() {
                Some(i) => i,
                None => break, // backpressure: all recv buffers checked out
            };

            idxs[n] = idx;
            iovs[n] = libc::iovec {
                iov_base: self.recv_pool.ptr(idx) as *mut libc::c_void,
                iov_len: self.recv_pool.slot_size(),
            };

            let h = &mut hdrs[n].msg_hdr;
            h.msg_name = std::ptr::addr_of_mut!(names[n]) as *mut libc::c_void;
            h.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            h.msg_iov = std::ptr::addr_of_mut!(iovs[n]);
            h.msg_iovlen = 1 as _;
            h.msg_control = ctrls[n].0.as_mut_ptr() as *mut libc::c_void;
            h.msg_controllen = ctrls[n].0.len() as _;
            n += 1;
        }

        if n == 0 {
            return Ok((0, false)); // backpressure: socket not drained
        }

        // SAFETY: hdrs[0..n] initialised above. socket is non-blocking
        let r = unsafe {
            libc::recvmmsg(
                self.socket.as_raw_fd(),
                hdrs.as_mut_ptr(),
                n as libc::c_uint,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut(),
            )
        };

        if r < 0 {
            let e = io::Error::last_os_error();
            for &i in &idxs[..n] {
                self.recv_pool.free(i);
            }
            if e.kind() == io::ErrorKind::WouldBlock {
                return Ok((0, true));
            }
            return Err(e);
        }

        let got = r as usize;
        for i in 0..got {
            let len = hdrs[i].msg_len as usize;
            // SAFETY: the kernel filled hdr for this slot. we only read it
            let (src, seg, ecn) = unsafe {
                let hdr = &hdrs[i].msg_hdr;
                let src = storage_to_addr(&names[i], hdr.msg_namelen)
                    .unwrap_or_else(|| SocketAddr::from(([0u8, 0, 0, 0], 0)));
                let seg = if self.gro_enabled && hdr.msg_controllen != 0 {
                    parse_gro(hdr)
                } else {
                    None
                };
                let ecn = ecn_from_control(hdr.msg_control, hdr.msg_controllen as usize);
                (src, seg, ecn)
            };
            out.push(self.recv_pool.buf(idxs[i], len, src, seg, ecn));
        }

        for &i in &idxs[got..n] {
            self.recv_pool.free(i);
        }

        Ok((got, got < n))
    }

    /// use private recvmsg_x() one macOS und iOS
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn drain_recv(&self, out: &mut Vec<RecvBuf>) -> io::Result<(usize, bool)> {
        const BATCH: usize = 64;
        let want = self.config.recv_batch_datagrams.min(BATCH);

        let mut idxs = [u32::MAX; BATCH];
        let mut iovs: [libc::iovec; BATCH] = unsafe { std::mem::zeroed() };
        let mut names: [libc::sockaddr_storage; BATCH] = unsafe { std::mem::zeroed() };
        let mut ctrls: [CmsgBuf; BATCH] = unsafe { std::mem::zeroed() };
        let mut hdrs: [darwin::MsgHdrX; BATCH] = unsafe { std::mem::zeroed() };

        let mut n = 0usize;
        while n < want {
            let idx = match self.recv_pool.alloc() {
                Some(i) => i,
                None => break,
            };

            idxs[n] = idx;
            iovs[n] = libc::iovec {
                iov_base: self.recv_pool.ptr(idx) as *mut libc::c_void,
                iov_len: self.recv_pool.slot_size(),
            };

            let h = &mut hdrs[n].hdr;
            h.msg_name = std::ptr::addr_of_mut!(names[n]) as *mut libc::c_void;
            h.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
            h.msg_iov = std::ptr::addr_of_mut!(iovs[n]);
            h.msg_iovlen = 1 as _;
            h.msg_control = ctrls[n].0.as_mut_ptr() as *mut libc::c_void;
            h.msg_controllen = ctrls[n].0.len() as _;
            n += 1;
        }

        if n == 0 {
            return Ok((0, false));
        }

        let r = unsafe {
            darwin::recvmsg_x(
                self.socket.as_raw_fd(),
                hdrs.as_mut_ptr(),
                n as libc::c_uint,
                libc::MSG_DONTWAIT,
            )
        };

        if r < 0 {
            let e = io::Error::last_os_error();
            for &i in &idxs[..n] {
                self.recv_pool.free(i);
            }

            if e.kind() == io::ErrorKind::WouldBlock {
                return Ok((0, true));
            }

            return Err(e);
        }

        let got = r as usize;
        for i in 0..got {
            let len = hdrs[i].datalen;
            let (src, ecn) = unsafe {
                let src = storage_to_addr(&names[i], hdrs[i].hdr.msg_namelen)
                    .unwrap_or_else(|| SocketAddr::from(([0u8, 0, 0, 0], 0)));
                let ecn =
                    ecn_from_control(hdrs[i].hdr.msg_control, hdrs[i].hdr.msg_controllen as usize);
                (src, ecn)
            };

            out.push(self.recv_pool.buf(idxs[i], len, src, None, ecn));
        }

        for &i in &idxs[got..n] {
            self.recv_pool.free(i);
        }

        Ok((got, got < n))
    }

    /// linux sendmmsg transmit path, one mmsghdr per batch. a batch packed with more
    /// than one segment carries a UDP_SEGMENT cmsg so the kernel re-cuts it
    #[cfg(target_os = "linux")]
    fn drain_send(&self) -> io::Result<()> {
        const BATCH: usize = 64;
        loop {
            let mut idxs = [u32::MAX; BATCH];
            let mut iovs: [libc::iovec; BATCH] = unsafe { std::mem::zeroed() };
            let mut ctrls: [CmsgBuf; BATCH] = unsafe { std::mem::zeroed() };
            let mut hdrs: [libc::mmsghdr; BATCH] = unsafe { std::mem::zeroed() };

            let mut n = 0usize;
            {
                let mut q = self.pending_send.borrow_mut();
                while n < BATCH {
                    let desc = match q.pop_front() {
                        Some(d) => d,
                        None => break,
                    };

                    idxs[n] = desc;
                    // SAFETY: desc is enqueued exclusively, meta set in `enqueue`
                    let meta = unsafe { &*self.send_meta[desc as usize].get() };
                    let bytes = self.send_pool.bytes(desc);
                    iovs[n] = libc::iovec {
                        iov_base: bytes.as_ptr() as *mut libc::c_void,
                        iov_len: bytes.len(),
                    };

                    let h = &mut hdrs[n].msg_hdr;
                    h.msg_name = std::ptr::addr_of!(meta.name) as *mut libc::c_void;
                    h.msg_namelen = meta.namelen;
                    h.msg_iov = std::ptr::addr_of_mut!(iovs[n]);
                    h.msg_iovlen = 1 as _;

                    if meta.seg > 0 {
                        // SAFETY: ctrls[n] is 8-aligned scratch large enough for one
                        // UDP_SEGMENT cmsg. every field the kernel reads is set here
                        unsafe {
                            h.msg_control = ctrls[n].0.as_mut_ptr() as *mut libc::c_void;
                            h.msg_controllen =
                                libc::CMSG_SPACE(std::mem::size_of::<u16>() as libc::c_uint) as _;
                            let cmsg = libc::CMSG_FIRSTHDR(h);
                            (*cmsg).cmsg_level = libc::SOL_UDP;
                            (*cmsg).cmsg_type = libc::UDP_SEGMENT;
                            (*cmsg).cmsg_len =
                                libc::CMSG_LEN(std::mem::size_of::<u16>() as libc::c_uint) as _;
                            (libc::CMSG_DATA(cmsg) as *mut u16).write_unaligned(meta.seg as u16);
                        }
                    }
                    n += 1;
                }
            }

            if n == 0 {
                return Ok(());
            }

            // SAFETY: hdrs[0..n] initialised. socket is non-blocking
            let r = unsafe {
                libc::sendmmsg(
                    self.socket.as_raw_fd(),
                    hdrs.as_mut_ptr(),
                    n as libc::c_uint,
                    libc::MSG_DONTWAIT,
                )
            };

            if r < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::WouldBlock {
                    self.requeue(&idxs[..n]);
                    return Ok(());
                }
                for &d in &idxs[..n] {
                    self.send_pool.reclaim(d);
                }
                return Err(e);
            }

            let sent = r as usize;
            for &d in &idxs[..sent] {
                self.send_pool.reclaim(d);
            }

            if sent < n {
                self.requeue(&idxs[sent..n]);
                return Ok(());
            }

            if self.pending_send.borrow().is_empty() {
                return Ok(());
            }
        }
    }

    /// batched send for apple devices
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn drain_send(&self) -> io::Result<()> {
        const BATCH: usize = 64;
        loop {
            let mut idxs = [u32::MAX; BATCH];
            // SAFETY: POD C structs. every field the kernel reads is set below
            let mut iovs: [libc::iovec; BATCH] = unsafe { std::mem::zeroed() };
            let mut hdrs: [darwin::MsgHdrX; BATCH] = unsafe { std::mem::zeroed() };

            let mut n = 0usize;
            {
                let mut q = self.pending_send.borrow_mut();
                while n < BATCH {
                    let desc = match q.pop_front() {
                        Some(d) => d,
                        None => break,
                    };
                    idxs[n] = desc;
                    // SAFETY: desc is enqueued exclusively, meta set in `enqueue`
                    let meta = unsafe { &*self.send_meta[desc as usize].get() };
                    let bytes = self.send_pool.bytes(desc);
                    iovs[n] = libc::iovec {
                        iov_base: bytes.as_ptr() as *mut libc::c_void,
                        iov_len: bytes.len(),
                    };
                    let h = &mut hdrs[n].hdr;
                    h.msg_name = std::ptr::addr_of!(meta.name) as *mut libc::c_void;
                    h.msg_namelen = meta.namelen;
                    h.msg_iov = std::ptr::addr_of_mut!(iovs[n]);
                    h.msg_iovlen = 1 as _;
                    hdrs[n].datalen = bytes.len();
                    n += 1;
                }
            }
            if n == 0 {
                return Ok(());
            }

            let r = unsafe {
                darwin::sendmsg_x(self.socket.as_raw_fd(), hdrs.as_ptr(), n as libc::c_uint, 0)
            };

            if r < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::WouldBlock {
                    self.requeue(&idxs[..n]);
                    return Ok(());
                }

                for &d in &idxs[..n] {
                    self.send_pool.reclaim(d);
                }

                return Err(e);
            }

            let sent = r as usize;
            for &d in &idxs[..sent] {
                self.send_pool.reclaim(d);
            }

            if sent < n {
                self.requeue(&idxs[sent..n]);
                return Ok(());
            }

            if self.pending_send.borrow().is_empty() {
                return Ok(());
            }
        }
    }

    /// block until the socket is readable, the waker fires, or deadline
    /// returns (socket_ready, waker_ready)
    fn block_on_fds(&self, deadline: Option<Instant>) -> io::Result<(bool, bool)> {
        let mut fds = [
            libc::pollfd {
                fd: self.socket.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: self.waker.read_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let rc = self.do_poll(&mut fds, deadline)?;
        if rc <= 0 {
            return Ok((false, false));
        }
        Ok((
            fds[0].revents & libc::POLLIN != 0,
            fds[1].revents & libc::POLLIN != 0,
        ))
    }

    /// ppoll() on linux
    #[cfg(target_os = "linux")]
    fn do_poll(&self, fds: &mut [libc::pollfd; 2], deadline: Option<Instant>) -> io::Result<i32> {
        let ts = deadline.map(|at| {
            let d = at.saturating_duration_since(Instant::now());
            libc::timespec {
                tv_sec: d.as_secs() as libc::time_t,
                tv_nsec: d.subsec_nanos() as libc::c_long,
            }
        });

        let tsp = ts.as_ref().map_or(std::ptr::null(), |t| t as *const _);
        let rc = unsafe { libc::ppoll(fds.as_mut_ptr(), 2, tsp, std::ptr::null()) };

        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                return Ok(0);
            }
            return Err(e);
        }
        Ok(rc)
    }

    /// macOS/iOS lack ppoll(), use poll
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn do_poll(&self, fds: &mut [libc::pollfd; 2], deadline: Option<Instant>) -> io::Result<i32> {
        let timeout_ms: libc::c_int = match deadline {
            Some(at) => {
                let d = at.saturating_duration_since(Instant::now());
                let ms = (d.as_millis()).min(libc::c_int::MAX as u128) as libc::c_int;
                if d.is_zero() {
                    0
                } else {
                    ms.max(1)
                }
            }
            None => -1,
        };

        let rc = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout_ms) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                return Ok(0);
            }
            return Err(e);
        }
        Ok(rc)
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
            backend: "poll_io",
            gso: self.gso_enabled,
            gro: self.gro_enabled,
        }
    }
}

/// walk control messages for the UDP_GRO cmsg carrying the coalesced segment size
#[cfg(target_os = "linux")]
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
