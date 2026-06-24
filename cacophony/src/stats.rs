use std::{collections::VecDeque, time::Duration};

use crate::connection::DurationDistribution;

const DEFAULT_DURATION_STATS_WINDOW: usize = 512;

#[derive(Debug)]
pub(crate) struct SlidingStats<T>
where
    T: Copy + Ord,
{
    order: VecDeque<T>,
    sorted: Vec<T>,
    capacity: usize,
}

impl<T> SlidingStats<T>
where
    T: Copy + Ord,
{
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            order: VecDeque::new(),
            sorted: Vec::new(),
            capacity,
        }
    }

    pub(crate) fn observe(&mut self, value: T) {
        if self.capacity == 0 {
            return;
        }
        if self.order.len() == self.capacity
            && let Some(removed) = self.order.pop_front()
            && let Ok(index) = self.sorted.binary_search(&removed)
        {
            self.sorted.remove(index);
        }
        let index = self.sorted.partition_point(|sample| *sample <= value);
        self.sorted.insert(index, value);
        self.order.push_back(value);
    }

    pub(crate) fn percentile(&self, percentile: usize) -> Option<T> {
        self.sorted
            .get(((self.sorted.len().saturating_sub(1)) * percentile) / 100)
            .copied()
    }

    pub(crate) fn max(&self) -> Option<T> {
        self.sorted.last().copied()
    }

    pub(crate) fn len(&self) -> usize {
        self.sorted.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.sorted.is_empty()
    }

    pub(crate) fn iter_sorted(&self) -> impl Iterator<Item = T> + '_ {
        self.sorted.iter().copied()
    }
}

impl<T> Default for SlidingStats<T>
where
    T: Copy + Ord,
{
    fn default() -> Self {
        Self::new(DEFAULT_DURATION_STATS_WINDOW)
    }
}

#[derive(Debug, Default)]
pub(crate) struct DurationStats {
    samples: SlidingStats<Duration>,
}

impl DurationStats {
    pub(crate) fn observe(&mut self, value: Duration) {
        self.samples.observe(value);
    }

    pub(crate) fn finish(self) -> DurationDistribution {
        if self.samples.is_empty() {
            return DurationDistribution::default();
        }
        let total = self
            .samples
            .iter_sorted()
            .fold(Duration::ZERO, |total, value| total + value);
        DurationDistribution {
            count: self.samples.len(),
            min: self.samples.iter_sorted().next(),
            avg: Some(duration_div(total, self.samples.len())),
            p95: self.samples.percentile(95),
            max: self.samples.max(),
        }
    }
}

fn duration_div(duration: Duration, divisor: usize) -> Duration {
    Duration::from_nanos((duration.as_nanos() / divisor as u128) as u64)
}
