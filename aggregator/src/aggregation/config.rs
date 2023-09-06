use halo2_proofs::{
    halo2curves::bn256::{Fq, Fr, G1Affine},
    plonk::{Column, ConstraintSystem, Instance},
};
use snark_verifier::{
    loader::halo2::halo2_ecc::{
        ecc::{BaseFieldEccChip, EccChip},
        fields::fp::FpConfig,
        halo2_base::gates::{flex_gate::FlexGateConfig, range::RangeConfig},
    },
    util::arithmetic::modulus,
};
use zkevm_circuits::{
    keccak_circuit::{KeccakCircuitConfig, KeccakCircuitConfigArgs},
    table::KeccakTable,
    util::{Challenges, SubCircuitConfig},
};

use crate::{
    constants::{BITS, LIMBS},
    param::ConfigParams,
    RlcConfig,
};

#[derive(Debug, Clone)]
#[rustfmt::skip]
/// Configurations for aggregation circuit.
/// This config is hard coded for BN256 curve.
pub struct AggregationConfig {
    /// Non-native field chip configurations
    pub base_field_config: FpConfig<Fr, Fq>,
    /// Keccak circuit configurations
    pub keccak_circuit_config: KeccakCircuitConfig<Fr>,    
    /// RLC config
    pub rlc_config: RlcConfig,
    /// Instance for public input; stores
    /// - accumulator from aggregation (12 elements)
    /// - batch_public_input_hash (32 elements)
    /// - the number of valid SNARKs (1 element)
    pub instance: Column<Instance>,
}

impl AggregationConfig {
    /// Build a configuration from parameters.
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        params: &ConfigParams,
        challenges: Challenges,
    ) -> Self {
        assert!(
            params.limb_bits == BITS && params.num_limbs == LIMBS,
            "For now we fix limb_bits = {BITS}, otherwise change code",
        );

        // RLC configuration
        let rlc_config = RlcConfig::configure(meta, challenges);

        // hash configuration for aggregation circuit
        let keccak_circuit_config = {
            let keccak_table = KeccakTable::construct(meta);

            let challenges_exprs = challenges.exprs(meta);
            let keccak_circuit_config_args = KeccakCircuitConfigArgs {
                keccak_table,
                challenges: challenges_exprs,
            };

            KeccakCircuitConfig::new(meta, keccak_circuit_config_args)
        };

        // base field configuration for aggregation circuit
        let base_field_config = FpConfig::configure(
            meta,
            params.strategy.clone(),
            &params.num_advice,
            &params.num_lookup_advice,
            params.num_fixed,
            params.lookup_bits,
            BITS,
            LIMBS,
            modulus::<Fq>(),
            0,
            params.degree as usize,
        );

        let columns = keccak_circuit_config.cell_manager.columns();
        log::info!("keccak uses {} columns", columns.len(),);

        // enabling equality for preimage column
        meta.enable_equality(columns[keccak_circuit_config.preimage_column_index].advice);
        // enable equality for the digest column
        meta.enable_equality(columns.last().unwrap().advice);
        // enable equality for the data RLC column
        meta.enable_equality(keccak_circuit_config.keccak_table.input_rlc);
        // enable equality for the input data len column
        meta.enable_equality(keccak_circuit_config.keccak_table.input_len);
        // enable equality for the is_final column
        meta.enable_equality(keccak_circuit_config.keccak_table.is_final);

        // Instance column stores public input column
        // - the accumulator
        // - the batch public input hash
        // - the number of valid SNARKs
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        Self {
            base_field_config,
            rlc_config,
            keccak_circuit_config,
            instance,
        }
    }

    /// Expose the instance column
    pub fn instance_column(&self) -> Column<Instance> {
        self.instance
    }

    /// Range gate configuration
    pub fn range(&self) -> &RangeConfig<Fr> {
        &self.base_field_config.range
    }

    /// Flex gate configuration
    pub fn flex_gate(&self) -> &FlexGateConfig<Fr> {
        &self.base_field_config.range.gate
    }

    /// Ecc gate configuration
    pub fn ecc_chip(&self) -> BaseFieldEccChip<G1Affine> {
        EccChip::construct(self.base_field_config.clone())
    }
}
