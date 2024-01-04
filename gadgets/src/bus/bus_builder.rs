use std::mem;

use super::{
    batch_assigner::{BatchAssigner, BusOpCounter},
    bus_chip::BusTerm,
    bus_codec::{BusCodecExpr, BusCodecVal, BusMessageF},
    Field,
};
use halo2_proofs::circuit::{Region, Value};

/// BusBuilder
#[derive(Debug)]
pub struct BusBuilder<F, M> {
    codec: BusCodecExpr<F, M>,
    terms: Vec<BusTerm<F>>,
}

impl<F: Field, M> BusBuilder<F, M> {
    /// Create a new bus.
    pub fn new(codec: BusCodecExpr<F, M>) -> Self {
        Self {
            codec,
            terms: vec![],
        }
    }

    /// Return the codec for messages on this bus.
    pub fn codec(&self) -> &BusCodecExpr<F, M> {
        &self.codec
    }

    /// Add a term to the bus.
    pub fn add_term(&mut self, term: BusTerm<F>) {
        self.terms.push(term);
    }

    /// Return the collected terms.
    pub fn build(self) -> Vec<BusTerm<F>> {
        self.terms
    }
}

/// BusAssigner
pub struct BusAssigner<F, M> {
    codec: BusCodecVal<F, M>,
    term_adder: TermAdder<F>,
    bus_op_counter: BusOpCounter<F, M>,
    batch_assigner: BatchAssigner<F, M>,
}

impl<F: Field, M: BusMessageF<F>> BusAssigner<F, M> {
    /// Create a new bus assigner with a maximum number of rows.
    pub fn new(codec: BusCodecVal<F, M>, n_rows: usize) -> Self {
        Self {
            batch_assigner: BatchAssigner::new(),
            codec,
            term_adder: TermAdder::new(0, n_rows),
            bus_op_counter: BusOpCounter::new(),
        }
    }

    /// Return the first offset supported by this BusAssigner.
    pub fn start_offset(&self) -> usize {
        self.term_adder.start_offset
    }

    /// Return the number of rows supported by this BusAssigner.
    pub fn n_rows(&self) -> usize {
        self.term_adder.terms.len()
    }

    /// Return the codec for messages on this bus.
    pub fn codec(&self) -> &BusCodecVal<F, M> {
        &self.codec
    }

    /// Return the op counter.
    pub fn op_counter(&mut self) -> &mut BusOpCounter<F, M> {
        &mut self.bus_op_counter
    }

    /// Return the batch assigner.
    pub fn batch_assigner(&mut self) -> &mut BatchAssigner<F, M> {
        &mut self.batch_assigner
    }

    /// Finish pending assignments in a region.
    pub fn finish_ports(&mut self, region: &mut Region<'_, F>) {
        let old_batch_assigner = mem::replace(&mut self.batch_assigner, BatchAssigner::new());

        old_batch_assigner.finish(region, self);
    }

    fn assert_finished(&self) {
        assert_eq!(self.batch_assigner.len(), 0, "finish_ports was not called");
        // TODO: better error handling.
    }

    /// Add a term value to the bus.
    pub fn add_term(&mut self, offset: usize, term: Value<F>) {
        self.term_adder.add_term(offset, term);
    }

    /// Return the collected terms.
    pub fn terms(&self) -> Value<&[F]> {
        self.assert_finished();
        assert_eq!(
            self.start_offset(),
            0,
            "cannot use the terms of a BusAssigner fork"
        );
        self.term_adder.terms()
    }

    /// Fork this BusAssigner for parallel assignment.
    pub fn fork(&self, start_offset: usize, n_rows: usize) -> Self {
        Self {
            batch_assigner: BatchAssigner::new(),
            codec: self.codec.clone(),
            term_adder: TermAdder::new(start_offset, n_rows),
            bus_op_counter: BusOpCounter::new(),
        }
    }

    /// Merge a fork of this BusAssigner back into it.
    pub fn merge(&mut self, fork: Self) {
        fork.assert_finished();
        self.term_adder.merge(fork.term_adder);
        self.bus_op_counter.merge(fork.bus_op_counter);
    }
}

struct TermAdder<F> {
    start_offset: usize,
    terms: Vec<F>,
    unknown: bool,
}

impl<F: Field> TermAdder<F> {
    /// Create a term adder with a maximum number of rows.
    fn new(start_offset: usize, n_rows: usize) -> Self {
        Self {
            start_offset,
            terms: vec![F::zero(); n_rows],
            unknown: false,
        }
    }

    /// Add a term value to the bus.
    fn add_term(&mut self, offset: usize, term: Value<F>) {
        let range = self.start_offset..self.start_offset + self.terms.len();
        assert!(
            range.contains(&offset),
            "offset={offset} out of bounds ({range:?})"
        );
        if self.unknown {
            return;
        }
        if term.is_none() {
            self.unknown = true;
            self.terms.clear();
        } else {
            term.map(|t| self.terms[offset - self.start_offset] += t);
        }
    }

    /// Return the collected terms.
    fn terms(&self) -> Value<&[F]> {
        if self.unknown {
            Value::unknown()
        } else {
            Value::known(&self.terms)
        }
    }

    /// Merge another TermAdder::terms() into self.
    fn merge(&mut self, other: Self) {
        if other.unknown {
            self.unknown = true;
            self.terms.clear();
        } else {
            assert!(other.start_offset >= self.start_offset);
            assert!(other.start_offset + other.terms.len() <= self.start_offset + self.terms.len());
            let start_index = other.start_offset - self.start_offset;

            for (index, term) in other.terms.into_iter().enumerate() {
                self.terms[start_index + index] += term;
            }
        }
    }
}
