use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    hash::Hash,
    marker::PhantomData,
};

use tokio::{sync::oneshot, time::Instant};

use crate::errors::{Error, Result};

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

    pub(crate) fn push_front(&mut self, item: T) -> Option<T> {
        let dropped = if self.items.len() >= self.capacity {
            self.items.pop_back()
        } else {
            None
        };
        self.items.push_front(item);
        dropped
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

pub(crate) struct DriverReply<T> {
    response: oneshot::Sender<Result<T>>,
}

impl<T> DriverReply<T> {
    pub(crate) fn new(response: oneshot::Sender<Result<T>>) -> Self {
        Self { response }
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.response.is_closed()
    }

    pub(crate) fn complete(self, result: Result<T>) {
        let _ = self.response.send(result);
    }

    pub(crate) fn complete_closed(self) {
        self.complete(Err(Error::Closed));
    }
}

struct DeadlineValue<T> {
    deadline: Instant,
    value: T,
}

pub(crate) struct BucketDeadlineQueue<B, T, const N: usize>
where
    B: QueueBucket + Clone + Eq + Hash,
{
    buckets: BucketQueue<B, DeadlineValue<T>, N>,
    deadlines: DeadlineSet<B>,
}

impl<B, T, const N: usize> Default for BucketDeadlineQueue<B, T, N>
where
    B: QueueBucket + Clone + Eq + Hash,
{
    fn default() -> Self {
        Self {
            buckets: BucketQueue::default(),
            deadlines: DeadlineSet::default(),
        }
    }
}

impl<B, T, const N: usize> BucketDeadlineQueue<B, T, N>
where
    B: QueueBucket + Clone + Eq + Hash,
{
    pub(crate) fn len(&self) -> usize {
        self.buckets.len()
    }

    #[cfg(test)]
    pub(crate) fn iter(&self) -> impl Iterator<Item = &T> {
        self.buckets.iter().map(|item| &item.value)
    }

    pub(crate) fn push(&mut self, bucket: B, value: T, deadline: Instant) {
        if self
            .buckets
            .back(bucket)
            .is_none_or(|queued| queued.deadline <= deadline)
        {
            self.buckets
                .push_back(bucket, DeadlineValue { deadline, value });
        } else {
            let index = self
                .buckets
                .position(bucket, |queued| queued.deadline > deadline)
                .expect("out-of-order queue insertion checked");
            self.buckets
                .insert(bucket, index, DeadlineValue { deadline, value });
        }
        self.refresh_bucket_deadline(bucket);
    }

    pub(crate) fn pop_expired(&mut self, now: Instant) -> Option<T> {
        let bucket = self.deadlines.pop_expired(now)?;
        self.pop_bucket_front(bucket)
    }

    pub(crate) fn pop_matching(&mut self, include: impl FnMut(&B) -> bool) -> Option<T> {
        let bucket = self.deadlines.first_matching(include)?;
        self.pop_bucket_front(bucket)
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        self.deadlines.next_deadline()
    }

    pub(crate) fn retain(&mut self, bucket: B, keep: impl FnMut(&T) -> bool) {
        let mut keep = keep;
        self.buckets.retain(bucket, |item| keep(&item.value));
        self.refresh_bucket_deadline(bucket);
    }

    fn pop_bucket_front(&mut self, bucket: B) -> Option<T> {
        let item = self.buckets.pop_front(bucket)?;
        self.refresh_bucket_deadline(bucket);
        Some(item.value)
    }

    fn refresh_bucket_deadline(&mut self, bucket: B) {
        if let Some(front) = self.buckets.front(bucket) {
            self.deadlines.insert(bucket, front.deadline);
        } else {
            self.deadlines.remove(&bucket);
        }
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

    pub(crate) fn first_matching(&self, mut include: impl FnMut(&K) -> bool) -> Option<K> {
        self.deadlines
            .values()
            .find_map(|keys| keys.iter().find(|key| include(key)).cloned())
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
