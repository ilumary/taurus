pub(crate) mod buffer;

/*#[cfg(feature = "uring_backend")]
mod uring;
#[cfg(feature = "uring_backend")]
pub(crate) use uring::Io;*/

#[cfg(not(feature = "uring_backend"))]
mod poll_io;
#[cfg(not(feature = "uring_backend"))]
pub(crate) use poll_io::Io;

use std::{
    cell::{Cell, RefCell},
    io,
    net::SocketAddr,
    os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd},
    rc::Rc,
    sync::Arc,
    time::Instant,
};

/// configuration for the backend
#[derive(Debug, Clone, Copy)]
pub struct BatchConfig {
    /// number of receive buffers / maximum receive operations in flight
    pub recv_slots: usize,

    /// max number of send batches queued before the oldest must complete
    pub send_slots: usize,

    /// bytes of send ring storage. must hold several batches of the largest send,
    /// which is `max_gso_segments * mtu` once gso is on
    pub send_ring: usize,

    /// maximum number of datagrams yielded by a single receive
    pub recv_batch_datagrams: usize,

    /// bytes per receive buffer. use the path MTU (e.g. 1500) normally, or 65535
    /// when `gro` is enabled or coalesced datagrams truncate
    pub recv_buf_size: usize,

    /// UDP generic segmentation offload, linux only
    pub gso: bool,

    /// UDP generic receive offload, linux only
    pub gro: bool,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            recv_slots: 512,
            send_slots: 512,
            send_ring: 4 << 20,
            recv_batch_datagrams: 64,
            recv_buf_size: 1500,
            gso: false,
            gro: false,
        }
    }
}

/// runtime feature set
#[derive(Debug, Clone, Copy)]
pub struct Capabilities {
    pub backend: &'static str,
    pub gso: bool,
    pub gro: bool,
}

/// the kernel re-cuts a UDP_SEGMENT buffer into at most this many datagrams
const MAX_GSO_SEGMENTS: usize = 64;

/// and the buffer itself may not exceed one IP datagram
const MAX_GSO_BYTES: usize = 65535;

/// a cheap, clonable, thread-safe handle used to interrupt a thread.
/// on linux this wraps an `eventfd`, elsewhere a non-blocking self-pipe
pub struct CrossThreadWaker {
    inner: Arc<WakerFds>,
}

struct WakerFds {
    /// polled for readability. for an eventfd this is also the fd written to, for a pipe it is the read end
    read: OwnedFd,

    /// the write end of a self-pipe. `None` for an eventfd
    write: Option<OwnedFd>,
}

impl CrossThreadWaker {
    #[cfg(target_os = "linux")]
    pub fn new() -> io::Result<Self> {
        let fd = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let read = unsafe { OwnedFd::from_raw_fd(fd) };
        Ok(Self {
            inner: Arc::new(WakerFds { read, write: None }),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn new() -> io::Result<Self> {
        let mut fds = [0 as libc::c_int; 2];
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }

        unsafe { libc::fcntl(fds[0], libc::F_SETFD, libc::FD_CLOEXEC) };
        unsafe { libc::fcntl(fds[1], libc::F_SETFD, libc::FD_CLOEXEC) };

        unsafe { libc::fcntl(fds[0], libc::F_SETFL, libc::O_NONBLOCK) };
        unsafe { libc::fcntl(fds[1], libc::F_SETFL, libc::O_NONBLOCK) };

        let read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        Ok(Self {
            inner: Arc::new(WakerFds {
                read,
                write: Some(write),
            }),
        })
    }

    pub fn wake(&self) {
        let fd = match &self.inner.write {
            Some(w) => w.as_raw_fd(),
            None => self.inner.read.as_raw_fd(),
        };

        let buf = 1u64.to_ne_bytes();

        loop {
            let rc = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
            if rc < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
    }

    #[inline]
    fn read_fd(&self) -> RawFd {
        self.inner.read.as_raw_fd()
    }

    fn drain(&self) {
        let fd = self.inner.read.as_raw_fd();
        let mut buf = [0u8; 64];
        loop {
            let rc = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if rc <= 0 || (rc as usize) < buf.len() {
                break;
            }
        }
    }
}

impl Clone for CrossThreadWaker {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

fn bind_reuseport(addr: SocketAddr) -> io::Result<socket2::Socket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_reuse_port(true)?;
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    enable_ecn_recv(sock.as_raw_fd(), addr.is_ipv4());
    Ok(sock)
}

fn enable_ecn_recv(fd: RawFd, is_ipv4: bool) {
    let on: libc::c_int = 1;
    let (level, opt) = if is_ipv4 {
        (libc::IPPROTO_IP, libc::IP_RECVTOS)
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVTCLASS)
    };

    unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
}

unsafe fn storage_to_addr(
    name: &libc::sockaddr_storage,
    len: libc::socklen_t,
) -> Option<SocketAddr> {
    let res = socket2::SockAddr::try_init(|sp, lp| {
        std::ptr::copy_nonoverlapping(
            name as *const libc::sockaddr_storage,
            sp as *mut libc::sockaddr_storage,
            1,
        );
        *lp = len;
        Ok::<(), io::Error>(())
    });

    match res {
        Ok(((), sa)) => sa.as_socket(),
        Err(_) => None,
    }
}

fn addr_to_storage(addr: SocketAddr, out: &mut libc::sockaddr_storage) -> libc::socklen_t {
    let sa = socket2::SockAddr::from(addr);
    unsafe {
        std::ptr::copy_nonoverlapping(
            sa.as_ptr() as *const u8,
            out as *mut libc::sockaddr_storage as *mut u8,
            sa.len() as usize,
        );
    }
    sa.len()
}

/// control message scratch for a single datagram
#[repr(C, align(8))]
struct CmsgBuf([u8; 256]);

const _: () = assert!(
    std::mem::align_of::<CmsgBuf>() >= std::mem::align_of::<libc::cmsghdr>(),
    "CmsgBuf must be at least as aligned as cmsghdr for CMSG_* pointer casts"
);

/// extract the 2-bit ecn codepoint from an `IP_TOS` (IPv4) or `IPV6_TCLASS` (IPv6) control message
/// returns 0 if not provided
unsafe fn ecn_from_control(control: *mut libc::c_void, controllen: usize) -> u8 {
    if control.is_null() || controllen == 0 {
        return 0;
    }

    let mut msg: libc::msghdr = std::mem::zeroed();
    msg.msg_control = control;
    msg.msg_controllen = controllen as _;

    let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
    while !cmsg.is_null() {
        let level = (*cmsg).cmsg_level;
        let ctype = (*cmsg).cmsg_type;

        if level == libc::IPPROTO_IP && ctype == libc::IP_TOS {
            return *(libc::CMSG_DATA(cmsg) as *const u8) & 0x03;
        }

        if level == libc::IPPROTO_IPV6 && ctype == libc::IPV6_TCLASS {
            let tc = (libc::CMSG_DATA(cmsg) as *const libc::c_int).read_unaligned();
            return (tc as u8) & 0x03;
        }

        cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
    }
    0
}

pub fn bind(addr: SocketAddr, config: &BatchConfig, waker: CrossThreadWaker) -> io::Result<Io> {
    Io::bind(addr, config, waker)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::time::Duration;

    pub use buffer::RecvBuf;

    fn cfg(gso: bool, gro: bool) -> BatchConfig {
        BatchConfig {
            recv_slots: 32,
            send_slots: 16,
            send_ring: 1 << 20,
            recv_batch_datagrams: 64,
            recv_buf_size: if gro { 65535 } else { 2048 },
            gso,
            gro,
        }
    }

    fn pair(gso: bool, gro: bool) -> (Io, Io, SocketAddr) {
        let a = "127.0.0.1:0".parse().unwrap();
        let tx = bind(a, &cfg(gso, gro), CrossThreadWaker::new().unwrap()).unwrap();
        let rx = bind(a, &cfg(gso, gro), CrossThreadWaker::new().unwrap()).unwrap();
        let dst = rx.local_addr().unwrap();
        (tx, rx, dst)
    }

    /// pump until `want` datagrams land or the deadline passes
    fn collect(rx: &Io, want: usize) -> Vec<buffer::RecvBuf> {
        let mut out = Vec::new();
        let end = Instant::now() + Duration::from_secs(2);
        while out.len() < want && Instant::now() < end {
            rx.poll(&mut out, Some(Instant::now() + Duration::from_millis(50)))
                .unwrap();
        }
        out
    }

    #[test]
    fn single_datagram_roundtrip() {
        let (tx, rx, dst) = pair(false, false);

        let seg = 1200;
        let mut b = tx.begin(seg).unwrap();
        b.segment(seg).unwrap()[..5].copy_from_slice(b"hello");
        b.commit(5);
        assert_eq!(b.count(), 1);
        tx.enqueue(b, dst, seg);
        tx.flush().unwrap();

        let got = collect(&rx, 1);
        assert_eq!(got.len(), 1, "one datagram must arrive");
        assert_eq!(got[0].data(), b"hello");

        // without gso a batch is capped at one segment
        let mut b = tx.begin(seg).unwrap();
        b.segment(seg).unwrap();
        b.commit(seg);
        assert!(b.segment(seg).is_none());
    }

    #[test]
    fn gso_batch_is_split_by_the_kernel() {
        let (tx, rx, dst) = pair(true, false);
        let seg = 1000;

        // three full segments and a short tail, one syscall, four datagrams
        let mut b = tx.begin(seg).unwrap();
        for i in 0..3u8 {
            b.segment(seg).unwrap().fill(i);
            b.commit(seg);
        }
        b.segment(seg).unwrap()[..10].fill(9);
        b.commit(10);
        assert_eq!(b.count(), 4);
        tx.enqueue(b, dst, seg);
        tx.flush().unwrap();

        let got = collect(&rx, 4);
        assert_eq!(got.len(), 4,);
        for (i, dg) in got.iter().enumerate().take(3) {
            assert_eq!(dg.data().len(), seg);
            assert!(dg.data().iter().all(|&x| x == i as u8));
        }
        assert_eq!(got[3].data().len(), 10);
    }

    #[test]
    fn gro_coalesces_into_one_slot() {
        let (tx, rx, dst) = pair(true, true);
        assert!(rx.capabilities().gro);
        let seg = 1000;

        let mut b = tx.begin(seg).unwrap();
        for _ in 0..4 {
            b.segment(seg).unwrap().fill(0x7A);
            b.commit(seg);
        }
        tx.enqueue(b, dst, seg);
        tx.flush().unwrap();

        // gro may or may not coalesce, but every byte must arrive either way
        let got = collect(&rx, 1);
        fn segs(b: &RecvBuf) -> std::slice::Chunks<'_, u8> {
            b.data().chunks(b.segment_size().unwrap_or(usize::MAX))
        }

        let total: usize = got.iter().flat_map(segs).map(<[u8]>::len).sum();
        let dgrams: usize = got.iter().flat_map(segs).count();

        assert_eq!(total, 4 * seg);
        assert_eq!(dgrams, 4);
        assert!(got.iter().flat_map(segs).all(|s| s.len() == seg),);
    }

    #[test]
    fn backpressure_and_reclaim() {
        // a ring that fits exactly two 1000-byte batches, and only two descriptors
        let mut c = cfg(false, false);
        c.send_ring = 2048;
        c.send_slots = 2;
        let tx = bind(
            "127.0.0.1:0".parse().unwrap(),
            &c,
            CrossThreadWaker::new().unwrap(),
        )
        .unwrap();
        let rx = bind(
            "127.0.0.1:0".parse().unwrap(),
            &c,
            CrossThreadWaker::new().unwrap(),
        )
        .unwrap();
        let dst = rx.local_addr().unwrap();
        let seg = 1000;

        for _ in 0..2 {
            let mut b = tx.begin(seg).unwrap();
            b.segment(seg).unwrap().fill(1);
            b.commit(seg);
            tx.enqueue(b, dst, seg);
        }
        assert!(tx.begin(seg).is_none(),);

        // flushing submits, and the completions release the regions
        tx.flush().unwrap();
        let got = collect(&rx, 2);
        assert_eq!(got.len(), 2);

        // reap the send completions on the tx side, which reclaims the ring
        let mut scratch = Vec::new();
        let end = Instant::now() + Duration::from_secs(2);
        while tx.begin(seg).is_none() && Instant::now() < end {
            tx.poll(
                &mut scratch,
                Some(Instant::now() + Duration::from_millis(50)),
            )
            .unwrap();
        }
        assert!(tx.begin(seg).is_some(),);
    }
}
