use halo2_proofs::{
    circuit::{AssignedCell, Layouter},
    halo2curves::bn256::Fr,
    plonk::{ConstraintSystem, Error},
};

#[derive(Clone, Debug)]
pub struct DecoderConfig;

pub struct AssignedDecoderConfigExports {
    pub encoded_rlc: AssignedCell<Fr, Fr>,
    pub decoded_rlc: AssignedCell<Fr, Fr>,
}

impl DecoderConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fr>) -> Self {
        DecoderConfig
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<Fr>,
    ) -> Result<AssignedDecoderConfigExports, Error> {
        unimplemented!()
    }
}
