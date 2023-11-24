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
            term_adder: TermAdder::new(n_rows),
            bus_op_counter: BusOpCounter::new(),
        }
    }

    /// Return the number of rows where the bus must be enabled.
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

    /// Add a term value to the bus.
    pub fn add_term(&mut self, offset: usize, term: Value<F>) {
        self.term_adder.add_term(offset, term);
    }

    /// Return the collected terms.
    pub fn terms(&self) -> Value<&[F]> {
        assert_eq!(self.batch_assigner.len(), 0, "finish_ports was not called");
        // TODO: better error handling.

        self.term_adder.terms()
    }
}

struct TermAdder<F> {
    terms: Vec<F>,
    unknown: bool,
}

impl<F: Field> TermAdder<F> {
    /// Create a term adder with a maximum number of rows.
    fn new(n_rows: usize) -> Self {
        Self {
            terms: vec![F::zero(); n_rows],
            unknown: false,
        }
    }

    /// Add a term value to the bus.
    fn add_term(&mut self, offset: usize, term: Value<F>) {
        assert!(
            offset < self.terms.len(),
            "offset={offset} out of bounds n_rows={}",
            self.terms.len()
        );
        if self.unknown {
            return;
        }
        if term.is_none() {
            self.unknown = true;
            self.terms.clear();
        } else {
            term.map(|t| self.terms[offset] += t);
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
}
