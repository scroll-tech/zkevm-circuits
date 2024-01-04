use std::ops::Neg;

use halo2_proofs::{
    circuit::Value,
    halo2curves::group::{ff, ff::BatchInvert},
};

/// Convert an isize to a field element.
pub fn from_isize<F: From<u64> + Neg<Output = F>>(x: isize) -> F {
    if x < 0 {
        -F::from((-x) as u64)
    } else {
        F::from(x as u64)
    }
}

/// TermBatch calculates helper witnesses, in batches for better performance.
pub struct HelperBatch<F, INFO> {
    denoms: Vec<(F, INFO)>,
    unknown: bool,
}

impl<F: ff::Field, INFO> HelperBatch<F, INFO> {
    /// Create a new term batch.
    pub fn new() -> Self {
        Self {
            denoms: vec![],
            unknown: false,
        }
    }

    /// Add a helper denominator to the batch. Some `info` can be attached for later use.
    pub fn add_denom(&mut self, denom: Value<F>, info: INFO) {
        if self.unknown {
            return;
        }
        if denom.is_none() {
            self.unknown = true;
            self.denoms.clear();
        } else {
            denom.map(|denom| self.denoms.push((denom, info)));
        }
    }

    /// Return the inverse of all denominators and their associated info.
    pub fn invert(mut self) -> Value<Vec<(F, INFO)>> {
        if self.unknown {
            Value::unknown()
        } else {
            self.denoms.iter_mut().map(|(d, _)| d).batch_invert();
            Value::known(self.denoms)
        }
    }

    pub fn len(&self) -> usize {
        self.denoms.len()
    }
}
