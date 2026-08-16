use std::{alloc::Layout, cell::Cell, net::SocketAddr, rc::Rc};

const NIL: u32 = u32::MAX;

/// fixed-size slot pool for receives, slots are returned to an intrusive free
/// list when their [`RecvBuf`] drops
pub struct RecvPool {
    base: *mut u8,
    layout: Layout,
    slot_size: usize,
    free_head: Cell<u32>,
}

impl RecvPool {
    pub fn new(slots: usize, slot_size: usize) -> Rc<Self> {
        assert!(slots > 0, "recv pool needs at least one slot");
        assert!(slots < NIL as usize, "too many recv slots");
        assert!(
            slot_size >= std::mem::size_of::<u32>(),
            "slot_size too small for the free-list link"
        );

        let layout = Layout::from_size_align(slots * slot_size, 8).unwrap();
        let base = unsafe { std::alloc::alloc(layout) };
        assert!(!base.is_null(), "recv pool out of memory");

        let pool = Rc::new(Self {
            base,
            layout,
            slot_size,
            free_head: Cell::new(NIL),
        });

        // push in reverse so slot 0 ends up at the head
        for i in (0..slots as u32).rev() {
            pool.free(i);
        }
        pool
    }

    #[inline]
    pub fn slot_size(&self) -> usize {
        self.slot_size
    }

    /// the iov_base handed to the kernel for `idx`
    #[inline]
    pub(super) fn ptr(&self, idx: u32) -> *mut u8 {
        unsafe { self.base.add(idx as usize * self.slot_size) }
    }

    /// reserve a slot for an in-flight recv or None when all slots are out
    #[inline]
    pub(super) fn alloc(&self) -> Option<u32> {
        let head = self.free_head.get();
        if head == NIL {
            return None;
        }

        let next = unsafe { (self.ptr(head) as *const u32).read_unaligned() };
        self.free_head.set(next);
        Some(head)
    }

    /// return a slot without producing a buffer for failed or unused recvs
    #[inline]
    pub(super) fn free(&self, idx: u32) {
        let head = self.free_head.get();
        unsafe { (self.ptr(idx) as *mut u32).write_unaligned(head) };
        self.free_head.set(idx);
    }

    /// wrap a completed recv slot, the slot frees when the buffer drops
    pub(super) fn buf(
        self: &Rc<Self>,
        idx: u32,
        len: usize,
        src: SocketAddr,
        segment_size: Option<usize>,
        ecn: u8,
    ) -> RecvBuf {
        debug_assert!(len <= self.slot_size);
        RecvBuf {
            pool: self.clone(),
            idx,
            len,
            src,
            segment_size,
            ecn,
        }
    }
}

impl Drop for RecvPool {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.base, self.layout) };
    }
}

/// owned reference to a recv slot. returned to the pool on drop
pub struct RecvBuf {
    /// reference to owning pool
    pool: Rc<RecvPool>,

    /// buffer index in owning pool
    idx: u32,

    /// length of the recv buffer
    len: usize,

    /// src address
    src: SocketAddr,

    /// `Some(seg)` if this buffer holds several GRO-coalesced datagrams each of
    /// `seg` bytes. `None` for a single datagram
    segment_size: Option<usize>,

    /// ecn bits
    ecn: u8,
}

impl RecvBuf {
    #[inline]
    pub fn data(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.pool.ptr(self.idx), self.len) }
    }

    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.pool.ptr(self.idx), self.len) }
    }

    #[inline]
    pub fn src(&self) -> SocketAddr {
        self.src
    }

    #[inline]
    pub fn ecn(&self) -> u8 {
        self.ecn
    }

    /// `Some(seg)` when GRO coalesced several datagrams of `seg` bytes into this
    /// slot, `None` for a single datagram
    #[inline]
    pub fn segment_size(&self) -> Option<usize> {
        self.segment_size
    }
}

impl Drop for RecvBuf {
    fn drop(&mut self) {
        self.pool.free(self.idx);
    }
}

/// one enqueued batch
#[derive(Clone, Copy)]
struct SendDesc {
    off: u32,
    len: u32,
    done: bool,
}

/// byte-ring send pool. a batch reserves a contiguous run and packs 1..N
/// equal-sized segments, released on send completion. the descriptor ring keeps
/// regions alive until the kernel signals completion and tolerates out-of-order
/// reclaim, which io_uring produces whenever a poll-armed send finishes late
pub struct SendPool {
    base: *mut u8,
    layout: Layout,
    cap: usize,

    /// reclaim frontier, start of the oldest in-flight region
    head: Cell<usize>,

    /// alloc frontier, end of the newest in-flight region
    tail: Cell<usize>,

    /// end of region A while the ring is wrapped, else `cap`. signals
    /// wrapping so head == tail is never ambiguous.
    wrap: Cell<usize>,

    /// in-flight batches in submission order
    desc: Box<[Cell<SendDesc>]>,
    desc_head: Cell<u32>,
    desc_len: Cell<u32>,
    desc_cap: u32,
}

impl SendPool {
    pub fn new(cap: usize, max_inflight: usize) -> Rc<Self> {
        assert!(cap > 0 && max_inflight > 0);
        assert!(cap <= u32::MAX as usize, "send ring larger than 4 GiB");
        assert!(max_inflight < NIL as usize);

        let layout = Layout::from_size_align(cap, 8).unwrap();
        let base = unsafe { std::alloc::alloc(layout) };
        assert!(!base.is_null(), "send pool out of memory");

        let desc = (0..max_inflight)
            .map(|_| {
                Cell::new(SendDesc {
                    off: 0,
                    len: 0,
                    done: false,
                })
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();

        Rc::new(Self {
            base,
            layout,
            cap,
            head: Cell::new(0),
            tail: Cell::new(0),
            wrap: Cell::new(cap),
            desc,
            desc_head: Cell::new(0),
            desc_len: Cell::new(0),
            desc_cap: max_inflight as u32,
        })
    }

    /// start a batch of segments up to `seg` bytes each, capped at `max_bytes`
    /// total. [`None`] when no contiguous run fits a segment or the descriptor ring
    /// is saturated, which is how backpressure surfaces
    pub fn begin(&self, seg: usize, max_bytes: usize) -> Option<SendBatch<'_>> {
        debug_assert!(seg > 0 && max_bytes >= seg);

        if self.desc_len.get() == self.desc_cap {
            return None;
        }

        // idle ring, reset for the largest possible contiguous run
        if self.desc_len.get() == 0 {
            self.head.set(0);
            self.tail.set(0);
            self.wrap.set(self.cap);
        }

        let head = self.head.get();
        let tail = self.tail.get();

        // a batch never spans the wrap, so it always lives in one contiguous run
        let (start, run_end, wraps) = if self.wrap.get() == self.cap {
            // linear, free space is [tail, cap) then [0, head)
            if self.cap - tail >= seg {
                (tail, self.cap, false)
            } else if head >= seg {
                (0, head, true)
            } else {
                return None;
            }
        } else {
            // wrapped, region A is [head, wrap) and region B is [0, tail)
            if head - tail >= seg {
                (tail, head, false)
            } else {
                return None;
            }
        };

        Some(SendBatch {
            pool: self,
            start,
            cursor: start,
            limit: run_end.min(start + max_bytes),
            count: 0,
            wraps,
        })
    }

    #[inline]
    pub(super) fn bytes(&self, desc: u32) -> &[u8] {
        let d = self.desc[desc as usize].get();
        unsafe { std::slice::from_raw_parts(self.base.add(d.off as usize), d.len as usize) }
    }

    /// mark a completed send and advance the reclaim frontier over the contiguous
    /// run of completed batches at the front
    pub(super) fn reclaim(&self, desc: u32) {
        let mut d = self.desc[desc as usize].get();
        d.done = true;
        self.desc[desc as usize].set(d);

        while self.desc_len.get() > 0 {
            let front_idx = self.desc_head.get();
            let front = self.desc[front_idx as usize].get();
            if !front.done {
                break;
            }

            let off = front.off as usize;
            if off < self.head.get() {
                self.wrap.set(self.cap);
            }

            self.head.set(off + front.len as usize);
            self.desc_head.set((front_idx + 1) % self.desc_cap);
            self.desc_len.set(self.desc_len.get() - 1);
        }

        if self.desc_len.get() == 0 {
            self.head.set(0);
            self.tail.set(0);
            self.wrap.set(self.cap);
        }
    }
}

impl Drop for SendPool {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.base, self.layout) };
    }
}

/// an open send batch. every segment uses the same `seg` and only the last may be shorter
pub struct SendBatch<'a> {
    pool: &'a SendPool,
    start: usize,
    cursor: usize,
    limit: usize,
    count: u32,
    wraps: bool,
}

impl SendBatch<'_> {
    /// reserve the next segment, up to `seg` writable bytes, or None when the run
    /// is exhausted and the batch cannot grow
    #[inline]
    pub fn segment(&mut self, seg: usize) -> Option<&mut [u8]> {
        if self.cursor + seg > self.limit {
            return None;
        }

        unsafe {
            Some(std::slice::from_raw_parts_mut(
                self.pool.base.add(self.cursor),
                seg,
            ))
        }
    }

    /// finalize the segment just written, `len` is the bytes actually used
    #[inline]
    pub fn commit(&mut self, len: usize) {
        debug_assert!(self.cursor + len <= self.limit);
        self.cursor += len;
        self.count += 1;
    }

    #[inline]
    pub fn count(&self) -> u32 {
        self.count
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.cursor - self.start
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.cursor == self.start
    }

    /// publish the batch, returns the descriptor to submit against and later hand
    /// to `reclaim`. dropping a batch instead simply abandons the reservation
    pub(super) fn finish(self) -> u32 {
        debug_assert!(self.count > 0, "finishing an empty batch");
        let pool = self.pool;

        // mark region A's end on a wrap, then publish
        if self.wraps {
            pool.wrap.set(pool.tail.get());
        }
        pool.tail.set(self.cursor);

        let idx = (pool.desc_head.get() + pool.desc_len.get()) % pool.desc_cap;
        pool.desc[idx as usize].set(SendDesc {
            off: self.start as u32,
            len: (self.cursor - self.start) as u32,
            done: false,
        });
        pool.desc_len.set(pool.desc_len.get() + 1);
        idx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push(pool: &SendPool, seg: usize, len: usize, fill: u8) -> u32 {
        let mut b = pool.begin(seg, seg).unwrap();
        b.segment(seg).unwrap().fill(fill);
        b.commit(len);
        b.finish()
    }

    #[test]
    fn recv_pool_alloc_free_and_gro() {
        let pool = RecvPool::new(3, 2048);
        assert_eq!(pool.slot_size(), 2048);
        let src: SocketAddr = "127.0.0.1:4433".parse().unwrap();

        // exhaust the pool
        let a = pool.alloc().expect("a");
        let b = pool.alloc().expect("b");
        let c = pool.alloc().expect("c");
        assert!(pool.alloc().is_none(), "pool must be empty now");

        // fill a slot with one datagram and read it back
        unsafe { std::ptr::write_bytes(pool.ptr(a), 0xAB, 100) };
        let mut ra = pool.buf(a, 100, src, None, 3);
        assert_eq!(ra.data().len(), 100);
        assert!(ra.data().iter().all(|&x| x == 0xAB));
        assert_eq!(ra.src(), src);
        assert_eq!(ra.ecn(), 3);
        ra.data_mut()[0] = 0xFF;
        assert_eq!(ra.data()[0], 0xFF);

        // a single datagram is one segment spanning the whole slice
        let segs: Vec<usize> = ra
            .data()
            .chunks(ra.segment_size().unwrap_or(usize::MAX))
            .map(<[u8]>::len)
            .collect();
        assert_eq!(segs, vec![100]);

        // an unused slot goes back without ever becoming a buffer
        pool.free(b);
        let d = pool.alloc().unwrap();
        assert!(pool.alloc().is_none());

        // GRO: one slot holding three coalesced 40-byte datagrams and a 25-byte tail
        pool.free(d);
        let g = pool.alloc().expect("g");
        unsafe { std::ptr::write_bytes(pool.ptr(g), 0x5A, 145) };
        let rg = pool.buf(g, 145, src, Some(40), 0);
        let segs: Vec<usize> = rg
            .data()
            .chunks(rg.segment_size().unwrap())
            .map(<[u8]>::len)
            .collect();
        assert_eq!(segs, vec![40, 40, 40, 25]);

        // dropping the buffers refills the pool
        drop(ra);
        drop(rg);
        pool.free(c);
        assert!(pool.alloc().is_some());
    }

    #[test]
    fn send_pool_fill_reclaim_and_gso() {
        let pool = SendPool::new(8192, 8);

        // a single 1000-byte datagram in a 1200-byte window
        let d0 = {
            let mut b = pool.begin(1200, 1200).unwrap();
            b.segment(1200).unwrap().fill(0x11);
            b.commit(1000);
            assert_eq!(b.count(), 1);
            assert_eq!(b.len(), 1000);
            b.finish()
        };
        assert_eq!(pool.desc_len.get(), 1);
        assert_eq!(pool.bytes(d0).len(), 1000);
        assert!(pool.bytes(d0).iter().all(|&x| x == 0x11));

        // a GSO batch: three full 1200-byte segments and a short 500-byte tail
        let d1 = {
            let mut b = pool.begin(1200, 1200 * 64).unwrap();
            for _ in 0..3 {
                b.segment(1200).unwrap().fill(0x22);
                b.commit(1200);
            }
            b.segment(1200).unwrap().fill(0x22);
            b.commit(500);
            assert_eq!(b.count(), 4);
            b.finish()
        };
        assert_eq!(pool.bytes(d1).len(), 3 * 1200 + 500);
        assert!(pool.bytes(d1).iter().all(|&x| x == 0x22));
        assert_eq!(pool.desc_len.get(), 2);

        // max_bytes caps the batch even when the ring has room
        {
            let mut b = pool.begin(100, 250).unwrap();
            for _ in 0..2 {
                b.segment(100).unwrap().fill(0x33);
                b.commit(100);
            }
            assert!(b.segment(100).is_none());
            assert_eq!(b.count(), 2);
            // dropped without finish, nothing is published
        }
        assert_eq!(pool.desc_len.get(), 2);

        // in-order reclaim drains the ring
        pool.reclaim(d0);
        assert_eq!(pool.desc_len.get(), 1);
        pool.reclaim(d1);
        assert_eq!(pool.desc_len.get(), 0);

        // fully idle, the whole ring is contiguous again
        let mut b = pool.begin(8192, 8192).unwrap();
        assert!(b.segment(8192).is_some());
        b.commit(8192);
        let d2 = b.finish();
        assert_eq!(pool.bytes(d2).len(), 8192);
        pool.reclaim(d2);
    }

    #[test]
    fn send_pool_wraparound_and_backpressure() {
        let pool = SendPool::new(1000, 8);
        let seg = 300;

        let d0 = push(&pool, seg, seg, 0);
        let d1 = push(&pool, seg, seg, 1);
        let d2 = push(&pool, seg, seg, 2);

        // [0,300) [300,600) [600,900), 100 bytes left and nothing reclaimed
        assert!(pool.begin(seg, seg).is_none());

        // reclaiming the front opens [0,300) for a wrapped batch
        pool.reclaim(d0);
        let d3 = push(&pool, seg, seg, 3);
        assert!(
            pool.bytes(d3).as_ptr() < pool.bytes(d1).as_ptr(),
            "d3 must wrap to the front of the ring"
        );
        assert!(pool.bytes(d3).iter().all(|&x| x == 3));
        assert!(pool.begin(seg, seg).is_none());

        // draining region A lets a further batch use region B
        pool.reclaim(d1);
        let d4 = push(&pool, seg, seg, 4);
        assert!(pool.bytes(d4).iter().all(|&x| x == 4));

        // crossing the region A -> B boundary clears the wrap
        pool.reclaim(d2);
        pool.reclaim(d3);
        pool.reclaim(d4);
        assert_eq!(pool.desc_len.get(), 0);

        // a max-size batch fits again after a full drain
        let mut b = pool.begin(1000, 1000).unwrap();
        assert!(b.segment(1000).is_some());
        b.commit(1000);
        pool.reclaim(b.finish());

        // the descriptor ring saturates independently of the byte ring
        let small = SendPool::new(4096, 2);
        let a = push(&small, 8, 8, 0);
        let _b = push(&small, 8, 8, 0);
        assert!(small.begin(8, 8).is_none());
        small.reclaim(a);
        assert!(small.begin(8, 8).is_some());
    }

    #[test]
    fn send_pool_out_of_order_reclaim() {
        let pool = SendPool::new(4096, 8);
        let seg = 1000;

        let a = push(&pool, seg, seg, 1); // [0,1000)
        let b = push(&pool, seg, seg, 2); // [1000,2000)
        let c = push(&pool, seg, seg, 3); // [2000,3000)
        assert_eq!(pool.desc_len.get(), 3);

        // completions arrive out of order while the front is still live
        pool.reclaim(b);
        pool.reclaim(c);
        assert_eq!(pool.desc_len.get(), 3);

        // the front completes and the whole done-prefix is reclaimed at once
        pool.reclaim(a);
        assert_eq!(pool.desc_len.get(), 0);

        // the space is fully recovered
        let mut big = pool.begin(4096, 4096).unwrap();
        assert!(big.segment(4096).is_some());
        big.commit(4096);
        pool.reclaim(big.finish());
    }
}
