use super::*;
use crate::param::ConfigParams as BatchCircuitConfigParams;

use halo2_proofs::plonk::{Column, Instance};
use snark_verifier::loader::halo2::halo2_ecc::{
    ecc::{BaseFieldEccChip, EccChip},
    fields::fp::FpConfig,
    halo2_base::gates::{flex_gate::FlexGateConfig, range::RangeConfig},
};

#[derive(Clone)]
pub struct RecursionConfig {
    pub base_field_config: FpConfig<Fr, Fq>,
    pub instance: Column<Instance>,
}

impl RecursionConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fr>, params: BatchCircuitConfigParams) -> Self {
        assert!(
            params.limb_bits == BITS && params.num_limbs == LIMBS,
            "For now we fix limb_bits = {}, otherwise change code",
            BITS
        );
        let base_field_config = FpConfig::configure(
            meta,
            params.strategy,
            &params.num_advice,
            &params.num_lookup_advice,
            params.num_fixed,
            params.lookup_bits,
            params.limb_bits,
            params.num_limbs,
            halo2_base::utils::modulus::<Fq>(),
            0,
            params.degree as usize,
        );

        let instance = meta.instance_column();
        meta.enable_equality(instance);

        Self {
            base_field_config,
            instance,
        }
    }

    pub fn gate(&self) -> &FlexGateConfig<Fr> {
        &self.base_field_config.range.gate
    }

    pub fn range(&self) -> &RangeConfig<Fr> {
        &self.base_field_config.range
    }

    pub fn ecc_chip(&self) -> BaseFieldEccChip<G1Affine> {
        EccChip::construct(self.base_field_config.clone())
    }
}
