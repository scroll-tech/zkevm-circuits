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
    table::{KeccakTable, RangeTable, U8Table},
    util::{Challenges, SubCircuitConfig},
};

use crate::{
    constants::{BITS, LIMBS},
    param::ConfigParams,
    BarycentricEvaluationConfig, BlobDataConfig, RlcConfig,
};

#[derive(Debug, Clone)]
#[rustfmt::skip]
/// Configurations for aggregation circuit.
/// This config is hard coded for BN256 curve.
pub struct AggregationConfig<const N_SNARKS: usize> {
    /// Non-native field chip configurations
    pub base_field_config: FpConfig<Fr, Fq>,
    /// Keccak circuit configurations
    pub keccak_circuit_config: KeccakCircuitConfig<Fr>,    
    /// RLC config
    pub rlc_config: RlcConfig,
    /// The blob data's config.
    pub blob_data_config: BlobDataConfig<N_SNARKS>,
    /// Config to do the barycentric evaluation on blob polynomial.
    pub barycentric: BarycentricEvaluationConfig,
    /// Instance for public input; stores
    /// - accumulator from aggregation (12 elements)
    /// - batch_public_input_hash (32 elements)
    /// - the number of valid SNARKs (1 element)
    pub instance: Column<Instance>,
}

impl<const N_SNARKS: usize> AggregationConfig<N_SNARKS> {
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

        // hash configuration for aggregation circuit
        let (keccak_table, keccak_circuit_config) = {
            let keccak_table = KeccakTable::construct(meta);

            let challenges_exprs = challenges.exprs(meta);
            let keccak_circuit_config_args = KeccakCircuitConfigArgs {
                keccak_table: keccak_table.clone(),
                challenges: challenges_exprs,
            };

            (
                keccak_table,
                KeccakCircuitConfig::new(meta, keccak_circuit_config_args),
            )
        };

        // RLC configuration
        let rlc_config = RlcConfig::configure(meta, &keccak_table, challenges);

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

        let barycentric = BarycentricEvaluationConfig::construct(base_field_config.range.clone());

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

        // Blob data.
        let u8_table = U8Table::construct(meta);
        let range_table = RangeTable::construct(meta);
        let challenges_expr = challenges.exprs(meta);
        let blob_data_config =
            BlobDataConfig::configure(meta, challenges_expr, u8_table, range_table, &keccak_table);

        // Instance column stores public input column
        // - the accumulator
        // - the batch public input hash
        // - the number of valid SNARKs
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        Self {
            base_field_config,
            rlc_config,
            blob_data_config,
            keccak_circuit_config,
            instance,
            barycentric,
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
