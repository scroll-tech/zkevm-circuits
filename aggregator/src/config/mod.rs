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
    table::{BitwiseOpTable, KeccakTable, Pow2Table, PowOfRandTable, RangeTable, U8Table},
    util::{Challenges, SubCircuitConfig},
};

use crate::{
    constants::{BITS, LIMBS},
    param::ConfigParams,
    BarycentricEvaluationConfig, BatchDataConfig, BlobDataConfig, DecoderConfig, DecoderConfigArgs,
    RlcConfig,
};

// TODO(rohit): inline doc
mod barycentric;
mod batch_data;
mod blob_data;
mod decoder;
mod plonk;

/// The config values required to configure the [`BatchCircuit`]. The `BatchCircuit` is configured
/// generic to the maximum number of SNARKs it can aggregate.
#[derive(Debug, Clone)]
pub struct BatchCircuitConfig<const N_SNARKS: usize> {
    /// Config used to configure the non-native field chip.
    pub base_field: FpConfig<Fr, Fq>,
    /// Config used to configure the [`KeccakCircuit`], that can compute the Keccak digest.
    pub keccak: KeccakCircuitConfig<Fr>,
    /// Config used to configure the [`RlcConfig`] that implements basic gates, with the purpose of
    /// computing the random linear combination (RLC) of input bytes with a given challenge value.
    pub rlc: RlcConfig,
    /// Config used to configure the [`BlobDataConfig`].
    pub blob_data: BlobDataConfig<N_SNARKS>,
    /// Config used to configure the [`BatchDataConfig`].
    pub batch_data: BatchDataConfig<N_SNARKS>,
    /// Config used to configure the [`DecoderConfig`], to decode relevant info from zstd-encoded
    /// data.
    pub decoder: DecoderConfig<1024, 512>,
    /// Config used to validate barycentric evaluation of the blob polynomial on a random challenge.
    pub barycentric: BarycentricEvaluationConfig,
    /// Instance for public input, in the following order:
    /// - accumulator from aggregation (12 elements)
    /// - chain id (1 element)
    /// - parent batch's state root (2 elements, split (hi, lo))
    /// - parent batch's batch hash (2 elements)
    /// - state root after applying current batch (2 elements)
    /// - current batch's hash (2 elements)
    /// - current batch's withdraw trie root (2 elements)
    pub instance: Column<Instance>,
}

impl<const N_SNARKS: usize> BatchCircuitConfig<N_SNARKS> {
    /// Configure the [`BatchCircuit`].
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        params: &ConfigParams,
        challenges: Challenges,
    ) -> Self {
        // Sanity check: we expect non-native field arithmetic to be configured with specific
        // values.
        assert!(
            params.limb_bits == BITS && params.num_limbs == LIMBS,
            "expected limb_bits={BITS}, num_limbs={LIMBS}, found limb_bits={limb_bits}, num_limbs={num_limbs}",
            limb_bits = params.limb_bits, num_limbs = params.num_limbs,
        );

        // Transform the challenge values into expressions.
        let challenge_exprs = challenges.exprs(meta);

        // Configure the Keccak Circuit.
        let (keccak_table, keccak) = {
            let keccak_table = KeccakTable::construct(meta);
            let config_args = KeccakCircuitConfigArgs {
                keccak_table: keccak_table.clone(),
                challenges: challenge_exprs.clone(),
            };
            let keccak = KeccakCircuitConfig::new(meta, config_args);

            // Since there are permutation checks on the following columns, we enable equality
            // check for those.
            let columns = keccak.cell_manager.columns();
            for column in [
                columns[keccak.preimage_column_index].advice, // preimage RLC
                columns.last().unwrap().advice,               // digest RLC
                keccak.keccak_table.input_rlc,                // input RLC
                keccak.keccak_table.input_len,                // input length
                keccak.keccak_table.is_final,                 // whether last row.
            ] {
                meta.enable_equality(column);
            }

            (keccak_table, keccak)
        };

        // Configure the RLC chip.
        let rlc = RlcConfig::configure(meta, &keccak_table, challenges);

        // Configure the non-native field arithmetic base chip.
        let base_field = FpConfig::configure(
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

        // Configure the Barycentric Evaluation gadget.
        let barycentric = BarycentricEvaluationConfig::construct(base_field.range.clone());

        // Configure the relation between batch and blob.
        let (u8_table, blob_data, batch_data) = {
            let u8_table = U8Table::construct(meta);
            let range_table = RangeTable::construct(meta);
            let blob_data = BlobDataConfig::configure(meta, &challenge_exprs, u8_table);
            let batch_data = BatchDataConfig::configure(
                meta,
                &challenge_exprs,
                u8_table,
                range_table,
                &keccak_table,
            );
            (u8_table, blob_data, batch_data)
        };

        // Configure the zstd-decoder.
        let decoder = {
            let pow_rand_table = PowOfRandTable::construct(meta, &challenge_exprs);
            let pow2_table = Pow2Table::construct(meta);
            let range8 = RangeTable::construct(meta);
            let range16 = RangeTable::construct(meta);
            let range512 = RangeTable::construct(meta);
            let range_block_len = RangeTable::construct(meta);
            let bitwise_op_table = BitwiseOpTable::construct(meta);
            DecoderConfig::configure(
                meta,
                &challenge_exprs,
                DecoderConfigArgs {
                    pow_rand_table,
                    pow2_table,
                    u8_table,
                    range8,
                    range16,
                    range512,
                    range_block_len,
                    bitwise_op_table,
                },
            )
        };

        // The instance column holds the `BatchCircuit`'s public input.
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        // Sanity check: we require that the degree of the `BatchCircuit` is no more than 9. In
        // general degree would be of the form 2n+1. This implies, for every inner config that is a
        // part of the `BatchCircuitConfig`, it MUST be constrained under degree <= 9.
        debug_assert!(
            meta.degree() <= 9,
            "expected degree <= 9, found degree={degree}",
            degree = meta.degree()
        );

        Self {
            base_field,
            keccak,
            rlc,
            barycentric,
            batch_data,
            blob_data,
            decoder,
            instance,
        }
    }

    /// Expose the instance column.
    pub fn instance_column(&self) -> Column<Instance> {
        self.instance
    }

    /// Range gate configuration.
    pub fn range(&self) -> &RangeConfig<Fr> {
        &self.base_field.range
    }

    /// Flex gate configuration.
    pub fn flex_gate(&self) -> &FlexGateConfig<Fr> {
        &self.base_field.range.gate
    }

    /// Construct and return an ECC gate configuration, using the base field config.
    pub fn ecc_chip(&self) -> BaseFieldEccChip<G1Affine> {
        EccChip::construct(self.base_field.clone())
    }
}

#[test]
fn batch_circuit_degree() {
    let param = crate::param::ConfigParams::aggregation_param();
    let mut cs = ConstraintSystem::<Fr>::default();
    let challenges = Challenges::construct_p1(&mut cs);
    BatchCircuitConfig::<{ crate::constants::MAX_AGG_SNARKS }>::configure(
        &mut cs, &param, challenges,
    );
    cs = cs.chunk_lookups();
    let stats = zkevm_circuits::util::circuit_stats(&cs);
    let degree = cs.degree();
    let phases = cs.max_phase();
    assert!(degree <= 9);
    assert!(phases <= 1);
}
