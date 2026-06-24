use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    hash::Hash,
    marker::PhantomData,
};

use tokio::time::Instant;

pub(crate) struct BoundedDeque<T> {
    items: VecDeque<T>,
    capacity: usize,
}

impl<T> BoundedDeque<T> {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            items: VecDeque::new(),
            capacity,
        }
    }

    pub(crate) fn pop_front(&mut self) -> Option<T> {
        self.items.pop_front()
    }

    pub(crate) fn push_back(&mut self, item: T) -> Option<T> {
        let dropped = if self.items.len() >= self.capacity {
            self.items.pop_front()
        } else {
            None
        };
        self.items.push_back(item);
        dropped
    }

    pub(crate) fn len(&self) -> usize {
        self.items.len()
    }

    pub(crate) fn has_capacity(&self) -> bool {
        self.items.len() < self.capacity
    }

    pub(crate) fn retain(&mut self, keep: impl FnMut(&T) -> bool) {
        self.items.retain(keep);
    }
}

pub(crate) trait QueueBucket: Copy {
    fn index(self) -> usize;
}

pub(crate) struct BucketQueue<B, T, const N: usize>
where
    B: QueueBucket,
{
    buckets: [VecDeque<T>; N],
    _bucket: PhantomData<fn(B)>,
}

impl<B, T, const N: usize> Default for BucketQueue<B, T, N>
where
    B: QueueBucket,
{
    fn default() -> Self {
        Self {
            buckets: std::array::from_fn(|_| VecDeque::new()),
            _bucket: PhantomData,
        }
    }
}

impl<B, T, const N: usize> BucketQueue<B, T, N>
where
    B: QueueBucket,
{
    pub(crate) fn len(&self) -> usize {
        self.buckets.iter().map(VecDeque::len).sum()
    }

    #[cfg(test)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.buckets.iter().flat_map(VecDeque::iter)
    }

    pub(crate) fn front(&self, bucket: B) -> Option<&T> {
        self.buckets[bucket.index()].front()
    }

    pub(crate) fn back(&self, bucket: B) -> Option<&T> {
        self.buckets[bucket.index()].back()
    }

    pub(crate) fn push_back(&mut self, bucket: B, item: T) {
        self.buckets[bucket.index()].push_back(item);
    }

    pub(crate) fn insert(&mut self, bucket: B, index: usize, item: T) {
        self.buckets[bucket.index()].insert(index, item);
    }

    pub(crate) fn pop_front(&mut self, bucket: B) -> Option<T> {
        self.buckets[bucket.index()].pop_front()
    }

    pub(crate) fn position(&self, bucket: B, predicate: impl FnMut(&T) -> bool) -> Option<usize> {
        self.buckets[bucket.index()].iter().position(predicate)
    }

    pub(crate) fn retain(&mut self, bucket: B, keep: impl FnMut(&T) -> bool) {
        self.buckets[bucket.index()].retain(keep);
    }
}

pub(crate) trait PendingRequest {
    type Key: Copy + Eq + Hash;

    fn key(&self) -> Self::Key;
    fn deadline(&self) -> Option<Instant>;
    fn is_closed(&self) -> bool;
    fn complete_timeout(self);
    fn complete_closed(self);
}

pub(crate) struct PendingRequestQueue<T>
where
    T: PendingRequest,
{
    order: VecDeque<T::Key>,
    requests: HashMap<T::Key, T>,
    deadlines: DeadlineSet<T::Key>,
}

impl<T> Default for PendingRequestQueue<T>
where
    T: PendingRequest,
{
    fn default() -> Self {
        Self {
            order: VecDeque::new(),
            requests: HashMap::new(),
            deadlines: DeadlineSet::default(),
        }
    }
}

impl<T> PendingRequestQueue<T>
where
    T: PendingRequest,
{
    pub(crate) fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    pub(crate) fn push_back(&mut self, request: T) {
        self.push(request, false);
    }

    pub(crate) fn push_front(&mut self, request: T) {
        self.push(request, true);
    }

    pub(crate) fn pop_front(&mut self) -> Option<T> {
        while let Some(key) = self.order.pop_front() {
            let Some(request) = self.requests.remove(&key) else {
                continue;
            };
            self.deadlines.remove(&key);
            if !request.is_closed() {
                return Some(request);
            }
        }
        None
    }

    pub(crate) fn discard_closed(&mut self) {
        let deadlines = &mut self.deadlines;
        self.requests.retain(|key, request| {
            if request.is_closed() {
                deadlines.remove(key);
                false
            } else {
                true
            }
        });
        let requests = &self.requests;
        self.order.retain(|key| requests.contains_key(key));
    }

    pub(crate) fn complete_expired(&mut self, now: Instant) {
        while let Some(key) = self.deadlines.pop_expired(now) {
            if let Some(request) = self.requests.remove(&key)
                && !request.is_closed()
            {
                request.complete_timeout();
            }
        }
    }

    pub(crate) fn complete_closed(&mut self) {
        for (_, request) in std::mem::take(&mut self.requests) {
            request.complete_closed();
        }
        self.order.clear();
        self.deadlines.clear();
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.deadlines.next_deadline()
    }

    fn push(&mut self, request: T, front: bool) {
        if request.is_closed() {
            return;
        }
        let key = request.key();
        if let Some(deadline) = request.deadline() {
            self.deadlines.insert(key, deadline);
        }
        if front {
            self.order.push_front(key);
        } else {
            self.order.push_back(key);
        }
        let old = self.requests.insert(key, request);
        debug_assert!(old.is_none(), "pending request keys are unique");
    }
}

pub(crate) struct DeadlineQueue<T> {
    items: BTreeMap<Instant, VecDeque<T>>,
    len: usize,
}

impl<T> Default for DeadlineQueue<T> {
    fn default() -> Self {
        Self {
            items: BTreeMap::new(),
            len: 0,
        }
    }
}

impl<T> DeadlineQueue<T> {
    pub(crate) fn push(&mut self, value: T, deadline: Instant) {
        self.items.entry(deadline).or_default().push_back(value);
        self.len += 1;
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.items.first_key_value().map(|(deadline, _)| *deadline)
    }

    pub(crate) fn pop_expired(&mut self, now: Instant) -> Option<T> {
        let deadline = *self.items.first_key_value()?.0;
        if deadline > now {
            return None;
        }
        let queue = self
            .items
            .get_mut(&deadline)
            .expect("deadline key came from this map");
        let value = queue.pop_front().expect("deadline buckets are never empty");
        if queue.is_empty() {
            self.items.remove(&deadline);
        }
        self.len -= 1;
        Some(value)
    }

    pub(crate) fn drain_all(&mut self, mut drain: impl FnMut(T)) {
        for (_, queue) in std::mem::take(&mut self.items) {
            for value in queue {
                drain(value);
            }
        }
        self.len = 0;
    }

    pub(crate) fn drain_expired(&mut self, now: Instant, mut expire: impl FnMut(T)) {
        while let Some(value) = self.pop_expired(now) {
            expire(value);
        }
    }
}

pub(crate) struct DeadlineSet<K>
where
    K: Clone + Eq + Hash,
{
    keys: HashMap<K, Instant>,
    deadlines: BTreeMap<Instant, HashSet<K>>,
}

impl<K> Default for DeadlineSet<K>
where
    K: Clone + Eq + Hash,
{
    fn default() -> Self {
        Self {
            keys: HashMap::new(),
            deadlines: BTreeMap::new(),
        }
    }
}

impl<K> DeadlineSet<K>
where
    K: Clone + Eq + Hash,
{
    pub(crate) fn insert(&mut self, key: K, deadline: Instant) {
        if let Some(old_deadline) = self.keys.insert(key.clone(), deadline) {
            if old_deadline == deadline {
                return;
            }
            self.remove_from_deadline(&key, old_deadline);
        }
        self.deadlines.entry(deadline).or_default().insert(key);
    }

    pub(crate) fn remove(&mut self, key: &K) -> bool {
        let Some(deadline) = self.keys.remove(key) else {
            return false;
        };
        self.remove_from_deadline(key, deadline);
        true
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.deadlines
            .first_key_value()
            .map(|(deadline, _)| *deadline)
    }

    pub(crate) fn pop_expired(&mut self, now: Instant) -> Option<K> {
        let deadline = *self.deadlines.first_key_value()?.0;
        if deadline > now {
            return None;
        }
        let key = self
            .deadlines
            .get(&deadline)
            .and_then(|keys| keys.iter().next())
            .cloned()
            .expect("deadline buckets are never empty");
        self.remove(&key);
        Some(key)
    }

    pub(crate) fn clear(&mut self) {
        self.keys.clear();
        self.deadlines.clear();
    }

    fn remove_from_deadline(&mut self, key: &K, deadline: Instant) {
        let Some(keys) = self.deadlines.get_mut(&deadline) else {
            return;
        };
        keys.remove(key);
        if keys.is_empty() {
            self.deadlines.remove(&deadline);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::time::Instant;

    use super::{DeadlineQueue, DeadlineSet};

    #[test]
    fn deadline_queue_preserves_duplicate_entries() {
        let now = Instant::now();
        let mut queue = DeadlineQueue::default();

        queue.push(7, now);
        queue.push(7, now);

        assert_eq!(queue.pop_expired(now), Some(7));
        assert_eq!(queue.pop_expired(now), Some(7));
        assert_eq!(queue.pop_expired(now), None);
    }

    #[test]
    fn deadline_set_replaces_existing_key_deadline() {
        let now = Instant::now();
        let mut set = DeadlineSet::default();

        set.insert(7, now + Duration::from_millis(10));
        set.insert(7, now + Duration::from_millis(20));

        assert_eq!(set.next_deadline(), Some(now + Duration::from_millis(20)));
        assert_eq!(set.pop_expired(now + Duration::from_millis(10)), None);
        assert_eq!(set.pop_expired(now + Duration::from_millis(20)), Some(7));
        assert_eq!(set.pop_expired(now + Duration::from_millis(20)), None);
    }
}
