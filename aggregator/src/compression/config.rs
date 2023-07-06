use halo2_proofs::{
    halo2curves::bn256::{Fq, Fr, G1Affine},
    plonk::{Column, ConstraintSystem, Instance},
};
use snark_verifier::loader::halo2::halo2_ecc::{
    ecc::{BaseFieldEccChip, EccChip},
    fields::fp::FpConfig,
    halo2_base::{
        gates::{flex_gate::FlexGateConfig, range::RangeConfig},
        utils::modulus,
    },
};

use crate::{
    constants::{BITS, LIMBS},
    param::ConfigParams,
};

#[derive(Clone, Debug)]
/// Configurations for compression circuit
/// This config is hard coded for BN256 curve
pub struct CompressionConfig {
    /// Non-native field chip configurations
    pub base_field_config: FpConfig<Fr, Fq>,
    /// Instance for public input
    pub instance: Column<Instance>,
}

impl CompressionConfig {
    /// Build a configuration from parameters.
    pub fn configure(meta: &mut ConstraintSystem<Fr>, params: ConfigParams) -> Self {
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
            modulus::<Fq>(),
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

    /// Range gate configuration
    pub fn range(&self) -> &RangeConfig<Fr> {
        &self.base_field_config.range
    }

    /// Flex gate configuration
    pub fn gate(&self) -> &FlexGateConfig<Fr> {
        &self.base_field_config.range.gate
    }

    /// Ecc gate configuration
    pub fn ecc_chip(&self) -> BaseFieldEccChip<G1Affine> {
        EccChip::construct(self.base_field_config.clone())
    }
}
