use smallvec::SmallVec;
use std::collections::BTreeMap;
use std::ops::{RangeInclusive, Bound};

/// max number of ranges stored inline before promoting to [`BTreeRangeSet`]
/// chosen so that `SmallVec<[(u64,u64); 4]>` fits in a single cache line
const MAX_INLINE_RANGES: usize = 4;

const DEMOTE_THRESHOLD: usize = MAX_INLINE_RANGES / 2;

/// sorted set of non-overlapping, non-adjacent inclusive `[start, end]` ranges
#[derive(Clone, Debug)]
pub enum RangeSet {
    Inline(InlineRangeSet),
    BTree(BTreeRangeSet),
}

/// stack-allocated variant
#[derive(Clone, Debug)]
pub struct InlineRangeSet {
    inner: SmallVec<[(u64, u64); MAX_INLINE_RANGES]>,
    capacity: usize,
}

/// heap-allocated variant backed by a `BTreeMap<start, end>`
#[derive(Clone, Debug)]
pub struct BTreeRangeSet {
    inner: BTreeMap<u64, u64>,
    capacity: usize,
}

impl RangeSet {
    pub fn new(capacity: usize) -> Self {
        RangeSet::Inline(InlineRangeSet {
            inner: SmallVec::new(),
            capacity,
        })
    }

    #[inline]
    pub fn insert(&mut self, val: RangeInclusive<u64>) {
        match self {
            RangeSet::BTree(btree) => btree.insert_range(val),
            RangeSet::Inline(inline) => inline.insert_range(val),
        }

        self.rebalance();
    }

    #[inline]
    pub fn push(&mut self, val: u64) {
        self.insert(val..=val);
    }

    /*/// returns `true` if `val` is contained in any tracked range
    #[inline]
    pub fn contains(&self, val: u64) -> bool {
        match self {
            RangeSet::Inline(inline) => inline.contains(val),
            RangeSet::BTree(btree) => btree.contains(val),
        }
    }*/

    /// remove all tracked values strictly below `val`
    pub fn remove_below(&mut self, val: u64) {
        match self {
            RangeSet::Inline(inline) => inline.remove_below(val),
            RangeSet::BTree(btree) => btree.remove_below(val),
        }

        self.rebalance();
    }

    /*/// the largest value in the set, or `None` if empty
    #[inline]
    pub fn largest(&self) -> Option<u64> {
        match self {
            RangeSet::Inline(inline) => inline.inner.last().map(|&(_, e)| e),
            RangeSet::BTree(btree) => btree.inner.values().next_back().copied(),
        }
    }*/

    /*/// the smallest value in the set, or `None` if empty
    #[inline]
    pub fn smallest(&self) -> Option<u64> {
        match self {
            RangeSet::Inline(inline) => inline.inner.first().map(|&(s, _)| s),
            RangeSet::BTree(btree) => btree.inner.keys().next().copied(),
        }
    }*/

    /// number of disjoint ranges currently stored
    #[inline]
    pub fn num_ranges(&self) -> usize {
        match self {
            RangeSet::Inline(inline) => inline.inner.len(),
            RangeSet::BTree(btree) => btree.inner.len(),
        }
    }

    /*/// `true` if the set contains no values
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.num_ranges() == 0
    }*/

    #[inline]
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = RangeInclusive<u64>> + '_ {
        let it: Box<dyn DoubleEndedIterator<Item = RangeInclusive<u64>>> = match self {
            RangeSet::Inline(i) => Box::new(i.inner.iter().map(|&(s, e)| s..=e)),
            RangeSet::BTree(b) => Box::new(b.inner.iter().map(|(&s, &e)| s..=e)),
        };
        it
    }

    #[inline]
    fn rebalance(&mut self) {
        match self {
            RangeSet::Inline(inline) => {
                if inline.inner.len() >= MAX_INLINE_RANGES {
                    let mut btree = BTreeMap::new();
                    for (s, e) in inline.inner.drain(..) {
                        btree.insert(s, e);
                    }
                    *self = RangeSet::BTree(BTreeRangeSet {
                        inner: btree,
                        capacity: inline.capacity,
                    });
                }
            }
            RangeSet::BTree(btree) => {
                if btree.inner.len() < DEMOTE_THRESHOLD {
                    let mut sv = SmallVec::new();
                    for (&s, &e) in &btree.inner {
                        sv.push((s, e));
                    }
                    *self = RangeSet::Inline(InlineRangeSet {
                        inner: sv,
                        capacity: btree.capacity,
                    });
                }
            }
        }
    }
}

impl InlineRangeSet {
    fn insert_range(&mut self, val: RangeInclusive<u64>) {
        let len = self.inner.len();
        let mut ms = *val.start();
        let mut me = *val.end();
        let mut first = len;
        let mut last = 0usize;

        for i in 0..len {
            let (s, e) = self.inner[i];

            if ms > e {
                continue;
            }

            if s <= *val.start() && *val.end() <= e {
                return; // duplicate
            }

            if s <= (*val.end()).saturating_add(1) && *val.start() <= e.saturating_add(1) {
                if i < first {
                    first = i;
                }
                last = i + 1;
                ms = ms.min(s);
                me = me.max(e);
            }
        }

        if first < last {
            self.inner[first] = (ms, me);
            if last > first + 1 {
                self.inner.drain(first + 1..last);
            }
        } else {
            let pos = self.inner.partition_point(|&(s, _)| s < *val.start());
            self.inner.insert(pos, (ms, me));
        }
    }

    /*#[inline]
    fn contains(&self, val: u64) -> bool {
        for &(s, e) in &self.inner {
            if val < s {
                return false;
            }
            if val <= e {
                return true;
            }
        }
        false
    }*/

    fn remove_below(&mut self, val: u64) {
        while let Some((start, end)) = self.inner.first_mut() {
            if val >= *end {
                self.inner.remove(0);
                continue;
            }

            *start = (val+1).max(*start);
            if *start > *end {
                self.inner.remove(0);
            }

            break;
        }
    }
}

impl BTreeRangeSet {
    pub fn insert_range(&mut self, item: RangeInclusive<u64>) {
        let mut start = *item.start();
        let mut end = *item.end();

        // check if preceding existing range overlaps or is adjacent
        if let Some(r) = self.prev(start) {
            if start <= (*r.end()).saturating_add(1) {
                self.inner.remove(r.start());
                start = std::cmp::min(start, *r.start());
                end = std::cmp::max(end, *r.end());
            }
        }

        // check if following existing ranges overlap or are adjacent
        while let Some(r) = self.next(start) {
            if *r.start() > end.saturating_add(1) {
                break;
            }

            // overlap or adjacent, merge them
            self.inner.remove(r.start());
            end = std::cmp::max(end, *r.end());
        }

        // capacity check
        if self.inner.len() >= self.capacity {
            self.inner.pop_first();
        }

        self.inner.insert(start, end);
    }

    fn prev(&self, item: u64) -> Option<RangeInclusive<u64>> {
        self.inner
            .range((Bound::Unbounded, Bound::Included(item)))
            .map(|(&s, &e)| s..=e)
            .next_back()
    }

    fn next(&self, item: u64) -> Option<RangeInclusive<u64>> {
        self.inner
            .range((Bound::Included(item), Bound::Unbounded))
            .map(|(&s, &e)| s..=e)
            .next()
    }

    /*#[inline]
    fn contains(&self, val: u64) -> bool {
        self.inner
            .range(..=val)
            .next_back()
            .is_some_and(|(_, &end)| val <= end)
    }*/

    fn remove_below(&mut self, val: u64) {
        let to_remove: Vec<RangeInclusive<u64>> = self
            .inner
            .range((Bound::Unbounded, Bound::Included(&val)))
            .map(|(&s, &e)| s..=e)
            .collect();

        for r in to_remove {
            self.inner.remove(r.start());

            if *r.end() > val {
                let start = val + 1;
                self.insert_range(start..=*r.end());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range_set_len(rs: &RangeSet) -> usize {
        match rs {
            RangeSet::Inline(inline) => inline.inner.len(),
            RangeSet::BTree(btree) => btree.inner.len(),
        }
    }

    fn expand(rs: &RangeSet) -> Vec<Vec<u64>> {
        let slices: Vec<(u64, u64)> = match rs {
            RangeSet::Inline(inline) => inline.inner.iter().copied().collect(),
            RangeSet::BTree(btree) => btree.inner.iter().map(|(&s, &e)| (s, e)).collect(),
        };
        slices.into_iter().map(|(s, e)| (s..=e).collect()).collect()
    }

    #[test]
    fn range_set_insert_non_overlapping() {
        let mut r = RangeSet::new(64);
        assert_eq!(range_set_len(&r), 0);
        let empty: Vec<Vec<u64>> = vec![];
        assert_eq!(expand(&r), empty);

        r.insert(4..=6);
        assert_eq!(range_set_len(&r), 1);
        assert_eq!(expand(&r), vec![vec![4, 5, 6]]);

        r.insert(9..=11);
        assert_eq!(range_set_len(&r), 2);
        assert_eq!(expand(&r), vec![vec![4, 5, 6], vec![9, 10, 11]]);
    }

    #[test]
    fn range_set_insert_contained() {
        let mut r = RangeSet::new(64);

        r.insert(4..=6);
        r.insert(9..=11);
        assert_eq!(expand(&r), vec![vec![4, 5, 6], vec![9, 10, 11]]);

        r.insert(4..=6);
        assert_eq!(range_set_len(&r), 2);
        assert_eq!(expand(&r), vec![vec![4, 5, 6], vec![9, 10, 11]]);

        r.insert(4..=5);
        assert_eq!(range_set_len(&r), 2);
        assert_eq!(expand(&r), vec![vec![4, 5, 6], vec![9, 10, 11]]);

        r.insert(5..=5);
        assert_eq!(range_set_len(&r), 2);
        assert_eq!(expand(&r), vec![vec![4, 5, 6], vec![9, 10, 11]]);

        r.insert(10..=10);
        assert_eq!(range_set_len(&r), 2);
        assert_eq!(expand(&r), vec![vec![4, 5, 6], vec![9, 10, 11]]);

        r.insert(9..=10);
        assert_eq!(range_set_len(&r), 2);
        assert_eq!(expand(&r), vec![vec![4, 5, 6], vec![9, 10, 11]]);
    }

    #[test]
    fn range_set_insert_overlapping() {
        let mut r = RangeSet::new(64);

        r.insert(3..=5);
        r.insert(9..=11);
        assert_eq!(expand(&r), vec![vec![3, 4, 5], vec![9, 10, 11]]);

        r.insert(5..=6);
        assert_eq!(range_set_len(&r), 2);
        assert_eq!(expand(&r), vec![vec![3, 4, 5, 6], vec![9, 10, 11]]);

        r.insert(10..=14);
        assert_eq!(range_set_len(&r), 2);
        assert_eq!(expand(&r), vec![vec![3, 4, 5, 6], vec![9, 10, 11, 12, 13, 14]]);

        r.insert(2..=4);
        assert_eq!(range_set_len(&r), 2);
        assert_eq!(expand(&r), vec![vec![2, 3, 4, 5, 6], vec![9, 10, 11, 12, 13, 14]]);

        r.insert(8..=9);
        assert_eq!(range_set_len(&r), 2);
        assert_eq!(expand(&r), vec![vec![2, 3, 4, 5, 6], vec![8, 9, 10, 11, 12, 13, 14]]);

        r.insert(6..=9);
        assert_eq!(range_set_len(&r), 1);
        assert_eq!(expand(&r), vec![vec![2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]]);
    }

    #[test]
    fn range_set_insert_overlapping_multi() {
        let mut r = RangeSet::new(64);

        r.insert(3..=5);
        r.insert(16..=19);
        assert_eq!(expand(&r), vec![vec![3, 4, 5], vec![16, 17, 18, 19]]);

        r.insert(10..=10);
        assert_eq!(range_set_len(&r), 3);
        assert_eq!(expand(&r), vec![vec![3, 4, 5], vec![10], vec![16, 17, 18, 19]]);

        assert!(matches!(r, RangeSet::Inline(_)));

        r.insert(13..=13);
        assert_eq!(range_set_len(&r), 4);
        assert_eq!(expand(&r), vec![vec![3, 4, 5], vec![10], vec![13], vec![16, 17, 18, 19]]);

        // Make sure it converted to a btree at capacity
        assert!(matches!(r, RangeSet::BTree(_)));

        r.insert(4..=16);
        assert_eq!(range_set_len(&r), 1);
        assert_eq!(expand(&r), vec![vec![3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]]);

        // Make sure it converted back to inline
        assert!(matches!(r, RangeSet::Inline(_)));
    }



    #[test]
    fn range_set_push_item() {
        let mut r = RangeSet::new(64);

        r.insert(4..=6);
        r.insert(9..=11);
        assert_eq!(range_set_len(&r), 2);
        assert_eq!(expand(&r), vec![vec![4, 5, 6], vec![9, 10, 11]]);

        r.push(15);
        assert_eq!(range_set_len(&r), 3);
        assert_eq!(expand(&r), vec![vec![4, 5, 6], vec![9, 10, 11], vec![15]]);

        r.push(15);
        assert_eq!(range_set_len(&r), 3);
        assert_eq!(expand(&r), vec![vec![4, 5, 6], vec![9, 10, 11], vec![15]]);

        r.push(1);
        assert_eq!(range_set_len(&r), 4);
        assert_eq!(expand(&r), vec![vec![1], vec![4, 5, 6], vec![9, 10, 11], vec![15]]);

        r.push(12);
        r.push(13);
        r.push(14);
        assert_eq!(range_set_len(&r), 3);
        assert_eq!(expand(&r), vec![vec![1], vec![4, 5, 6], vec![9, 10, 11, 12, 13, 14, 15]]);

        r.push(2);
        r.push(3);
        assert_eq!(range_set_len(&r), 2);
        assert_eq!(expand(&r), vec![vec![1, 2, 3, 4, 5, 6], vec![9, 10, 11, 12, 13, 14, 15]]);

        r.push(8);
        r.push(7);
        assert_eq!(range_set_len(&r), 1);
        assert_eq!(expand(&r), vec![vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]]);
    }

    #[test]
    fn prev_to() {
        let mut r = BTreeRangeSet {
            inner: Default::default(),
            capacity: usize::MAX,
        };

        r.insert_range(4..=6);
        r.insert_range(9..=11);

        assert_eq!(r.prev(2), None);
        assert_eq!(r.prev(4), Some(4..=6));
        assert_eq!(r.prev(15), Some(9..=11));
        assert_eq!(r.prev(5), Some(4..=6));
        assert_eq!(r.prev(8), Some(4..=6));
    }

    #[test]
    fn next_to() {
        let mut r = BTreeRangeSet {
            inner: Default::default(),
            capacity: usize::MAX,
        };

        r.insert_range(4..=6);
        r.insert_range(9..=11);

        assert_eq!(r.next(2), Some(4..=6));
        assert_eq!(r.next(12), None);
        assert_eq!(r.next(15), None);
        assert_eq!(r.next(5), Some(9..=11));
        assert_eq!(r.next(8), Some(9..=11));
    }

    #[test]
    fn range_set_remove_below() {
        let mut r = RangeSet::new(64);

        r.insert(3..=5);
        r.insert(9..=10);
        r.insert(13..=13);
        r.insert(16..=19);
        assert_eq!(expand(&r), vec![vec![3, 4, 5], vec![9, 10], vec![13], vec![16, 17, 18, 19]]);

        r.remove_below(2);
        assert_eq!(expand(&r), vec![vec![3, 4, 5], vec![9, 10], vec![13], vec![16, 17, 18, 19]]);

        r.remove_below(4);
        assert_eq!(expand(&r), vec![vec![5], vec![9, 10], vec![13], vec![16, 17, 18, 19]]);

        r.remove_below(6);
        assert_eq!(expand(&r), vec![vec![9, 10], vec![13], vec![16, 17, 18, 19]]);

        r.remove_below(10);
        assert_eq!(expand(&r), vec![vec![13], vec![16, 17, 18, 19]]);

        r.remove_below(17);
        assert_eq!(expand(&r), vec![vec![18, 19]]);

        r.remove_below(18);
        assert_eq!(expand(&r), vec![vec![19]]);

        r.remove_below(20);

        let empty: Vec<Vec<u64>> = vec![];
        assert_eq!(expand(&r), empty);
    }
}
