//! Define IntDecomposition to decompose int into byte limbs
use eth_types::{Field, ToLittleEndian, H160, U256};
use gadgets::util::{sum, Expr};
use halo2_proofs::{
    circuit::{AssignedCell, Value},
    plonk::{Error, Expression},
};
use itertools::Itertools;

use crate::evm_circuit::{
    param::{MAX_N_BYTES_INTEGER, N_BYTES_HALF_WORD},
    util::{rlc, CachedRegion, Cell},
};

use super::word::{Word, WordExpr};

#[derive(Clone, Debug)]
/// IntDecomposition decompose integer into byte limbs
pub struct IntDecomposition<F, const N_LIMBS: usize> {
    /// inner cells in little-endian for synthesis
    pub limbs: [Cell<F>; N_LIMBS],
}

impl<F: Field, const N_LIMBS: usize> IntDecomposition<F, N_LIMBS> {
    /// new by cell limbs
    pub fn new(limbs: [Cell<F>; N_LIMBS]) -> Self {
        Self { limbs }
    }

    /// assign bytes to cells
    pub fn assign<const N_BYTES: usize>(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        bytes: Option<[u8; N_BYTES]>,
    ) -> Result<Vec<Option<AssignedCell<F, F>>>, Error> {
        assert!(N_BYTES >= N_LIMBS);
        if let Some(bytes) = bytes {
            if N_BYTES > N_LIMBS {
                for byte in &bytes[N_LIMBS..] {
                    assert_eq!(*byte, 0);
                }
            }
        }
        bytes.map_or(Err(Error::Synthesis), |bytes| {
            self.limbs
                .iter()
                .zip(bytes.iter())
                .map(|(cell, byte)| {
                    cell.assign(region, offset, Value::known(F::from(*byte as u64)))
                })
                .collect()
        })
    }

    /// assign h160 to cells
    pub fn assign_h160(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        h160: H160,
    ) -> Result<Vec<Option<AssignedCell<F, F>>>, Error> {
        let mut bytes = *h160.as_fixed_bytes();
        bytes.reverse();
        self.assign(region, offset, Some(bytes))
    }

    /// assign u256 to cells
    pub fn assign_u256(
        &self,
        region: &mut CachedRegion<'_, '_, F>,
        offset: usize,
        u256: U256,
    ) -> Result<Vec<Option<AssignedCell<F, F>>>, Error> {
        self.assign(region, offset, Some(u256.to_le_bytes()))
    }

    /// assign all limbs into one expression
    pub fn sum_expr(&self) -> Expression<F> {
        sum::expr(self.limbs.clone())
    }
}

impl<F: Field, const N_LIMBS: usize> Expr<F> for IntDecomposition<F, N_LIMBS> {
    fn expr(&self) -> Expression<F> {
        assert!(N_LIMBS <= MAX_N_BYTES_INTEGER);
        rlc::expr(&self.limbs.clone().map(|limb| limb.expr()), 256.expr())
    }
}

impl<F: Field, const N_LIMBS: usize> WordExpr<F> for IntDecomposition<F, N_LIMBS> {
    fn to_word(&self) -> Word<Expression<F>> {
        let exprs = self
            .limbs
            .clone()
            .map(|x| x.expr())
            .chunks(N_BYTES_HALF_WORD)
            .map(|chunk| rlc::expr(chunk, 256.expr()))
            .collect::<Vec<Expression<F>>>();
        Word::new(
            (0..2)
                .map(|id| exprs.get(id).unwrap_or(&0.expr()).clone())
                .collect_vec()
                .try_into()
                .unwrap(),
        )
    }
}
