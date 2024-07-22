use crate::params::ConfigParams;
use ce_snark_verifier::{
    halo2_base::gates::{
        flex_gate::{FlexGateConfig, FlexGateConfigParams},
        range::RangeConfig,
    },
    halo2_ecc::{ecc::BaseFieldEccChip, fields::fp::FpConfig},
};
use ce_snark_verifier_sdk::{BITS, LIMBS};
use halo2_proofs::plonk::{Column, ConstraintSystem, Instance};
use halo2curves::bn256::{Fr, G1Affine};

#[derive(Clone, Debug)]
/// Configurations for compression circuit
/// This config is hard coded for BN256 curve
pub struct CompressionConfig {
    /// Non-native field chip configurations
    pub base_field_config: FpConfig<Fr>,
    /// Instance for public input
    pub instance: Column<Instance>,
}

impl CompressionConfig {
    /// Build a configuration from parameters.
    pub fn configure(meta: &mut ConstraintSystem<Fr>, params: ConfigParams) -> Self {
        assert!(
            params.limb_bits == BITS && params.num_limbs == LIMBS,
            "For now we fix limb_bits = {BITS}, otherwise change code",
        );

        let gate_params = FlexGateConfigParams {
            k: params.degree.try_into().unwrap(),
            num_fixed: params.num_fixed,
            num_advice_per_phase: params.num_advice,
        };

        let base_field_config = FpConfig::configure(
            meta,
            gate_params,
            &params.num_lookup_advice,
            params.lookup_bits,
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
        &self.base_field_config
    }

    /// Flex gate configuration
    pub fn gate(&self) -> &FlexGateConfig<Fr> {
        &self.base_field_config.gate
    }

    /// Ecc gate configuration
    pub fn ecc_chip(&self) -> BaseFieldEccChip<G1Affine> {
        unimplemented!()
        // EccChip::construct(self.base_field_config.clone())
    }
}
