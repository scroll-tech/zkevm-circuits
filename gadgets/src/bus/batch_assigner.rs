use super::{
    bus_builder::BusAssigner, bus_codec::BusMessageF, bus_port::BusOpF, util::HelperBatch, Field,
};
use halo2_proofs::circuit::{Region, Value};
use std::{
    collections::{
        hash_map::Entry::{Occupied, Vacant},
        HashMap,
    },
    marker::PhantomData,
};

/// Assigners are used to delay the assignment until helper values are computed.
pub trait Assigner<F: Field>: Send + Sync {
    /// Given the helper value, assign ports and return (offset, term).
    #[must_use = "terms must be added to the bus"]
    fn assign(&self, region: &mut Region<'_, F>, helper: F) -> (usize, F);
}

/// BatchAssigner computes and assigns terms into helper cells and the bus.
pub struct BatchAssigner<F, M> {
    assigners: HelperBatch<F, Box<dyn Assigner<F>>>,
    _marker: PhantomData<M>,
}

impl<F: Field, M: BusMessageF<F>> Default for BatchAssigner<F, M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field, M: BusMessageF<F>> BatchAssigner<F, M> {
    /// Create a new BatchAssigner.
    pub fn new() -> Self {
        Self {
            assigners: HelperBatch::new(),
            _marker: PhantomData,
        }
    }

    /// Execute an assignment later, with the inverse of `denom`.
    pub fn assign_later(&mut self, cmd: Box<dyn Assigner<F>>, denom: Value<F>) {
        self.assigners.add_denom(denom, cmd)
    }

    /// Assign the helper cells and report the terms to the bus.
    pub fn finish(self, region: &mut Region<'_, F>, bus_assigner: &mut BusAssigner<F, M>) {
        self.assigners.invert().map(|commands| {
            for (helper, command) in commands {
                let (offset, term) = command.assign(region, helper);
                bus_assigner.add_term(region.global_offset(offset), Value::known(term));
            }
        });
    }

    pub fn len(&self) -> usize {
        self.assigners.len()
    }
}

/// OpCounter tracks the messages received, to help generating the corresponding sends.
#[derive(Clone, Debug)]
pub struct BusOpCounter<F, M> {
    counts: HashMap<M, isize>,
    _marker: PhantomData<(F, M)>,
}

impl<F: Field, M: BusMessageF<F>> Default for BusOpCounter<F, M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field, M: BusMessageF<F>> BusOpCounter<F, M> {
    /// Create a new BusOpCounter.
    pub fn new() -> Self {
        Self {
            counts: HashMap::new(),
            _marker: PhantomData,
        }
    }

    /// Record an operation that went on the bus.
    pub fn track_op(&mut self, op: &BusOpF<M>) {
        if op.count() == 0 {
            return;
        }
        match self.counts.entry(op.message()) {
            Occupied(mut entry) => {
                let count = entry.get_mut();
                *count += op.count();
                if *count == 0 {
                    entry.remove();
                }
            }
            Vacant(entry) => {
                entry.insert(op.count());
            }
        };
    }

    /// Count how many times a message was received (net of sends).
    pub fn count_receives(&self, message: &M) -> isize {
        (-self.count_ops(message)).max(0)
    }

    /// Count how many times a message was sent (net of receives).
    pub fn count_sent(&self, message: &M) -> isize {
        self.count_ops(message).max(0)
    }

    /// Count how many times a message was sent (net positive) or received (net negative).
    fn count_ops(&self, message: &M) -> isize {
        *self.counts.get(message).unwrap_or(&0)
    }

    /// Return true if all messages received have been sent.
    pub fn is_complete(&self) -> bool {
        self.counts.is_empty()
    }

    /// Merge another instance of BusOpCounter into self. The counts are accumulated.
    pub fn merge(&mut self, other: Self) {
        for (key, other_count) in other.counts {
            *self.counts.entry(key).or_insert(0) += other_count;
        }
    }
}
