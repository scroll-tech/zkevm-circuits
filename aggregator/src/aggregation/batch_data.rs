use crate::{
    aggregation::rlc::POWS_OF_256, blob_consistency::BLOB_WIDTH, constants::N_BYTES_U256,
    BatchHash, ChunkInfo, RlcConfig,
};
use eth_types::{H256, U256};
use ethers_core::utils::keccak256;
use halo2_ecc::bigint::CRTInteger;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, SecondPhase, Selector},
    poly::Rotation,
};
use itertools::Itertools;
use std::iter::{once, repeat};
use zkevm_circuits::{
    table::{KeccakTable, LookupTable, RangeTable, U8Table},
    util::{Challenges, Expr},
};

/// The number data bytes we pack each BLS12-381 scalar into. The most-significant byte is 0.
pub const N_DATA_BYTES_PER_COEFFICIENT: usize = 31;

/// The number of bytes that we can fit in a blob. Note that each coefficient is represented in 32
/// bytes, however, since those 32 bytes must represent a BLS12-381 scalar in its canonical form,
/// we explicitly set the most-significant byte to 0, effectively utilising only 31 bytes.
pub const N_BLOB_BYTES: usize = BLOB_WIDTH * N_DATA_BYTES_PER_COEFFICIENT;

/// Allow up to 5x compression via zstd encoding of the batch data.
const N_BATCH_BYTES: usize = N_BLOB_BYTES * 5;

/// The number of rows to encode number of valid chunks (num_valid_snarks) in a batch, in the Blob
/// Data config. Since num_valid_chunks is u16, we use 2 bytes/rows.
const N_ROWS_NUM_CHUNKS: usize = 2;

/// The number of rows to encode chunk size (u32).
const N_ROWS_CHUNK_SIZE: usize = 4;

#[derive(Clone, Debug)]
pub struct BatchDataConfig<const N_SNARKS: usize> {
    /// The byte value at this row.
    byte: Column<Advice>,
    /// The accumulator serves several purposes.
    /// 1. For the metadata section, the accumulator holds the running linear combination of the
    ///    chunk size.
    /// 2. For the chunk data section, the accumulator holds the incremental chunk size, which
    ///    resets to 1 if we encounter a chunk boundary. The accumulator here is referenced while
    ///    doing a lookup to the Keccak table that requires the input length.
    accumulator: Column<Advice>,
    /// An increasing counter that denotes the chunk ID. The chunk ID is from [1, N_SNARKS].
    chunk_idx: Column<Advice>,
    /// A boolean witness that is set only when we encounter the end of a chunk. We enable a lookup
    /// to the Keccak table when the boundary is met.
    is_boundary: Column<Advice>,
    /// A running accumulator of the boundary counts.
    boundary_count: Column<Advice>,
    /// A boolean witness to indicate padded rows at the end of the data section.
    is_padding: Column<Advice>,
    /// A running accumulator of the RLC of every byte seen so far.
    bytes_rlc: Column<Advice>,
    /// Represents the running random linear combination of bytes seen so far, that are a part of
    /// the preimage to the Keccak hash. It resets whenever we encounter a chunk boundary.
    preimage_rlc: Column<Advice>,
    /// Represents the random linear combination of the Keccak digest. This has meaningful values
    /// only at the rows where we actually do the Keccak lookup.
    digest_rlc: Column<Advice>,
    /// Boolean to let us know we are in the "chunk data" section.
    pub data_selector: Selector,
    /// Boolean to let us know we are in the "digest rlc" section.
    pub hash_selector: Selector,
    /// Fixed table that consists of [0, 256).
    u8_table: U8Table,
    /// Fixed table that consists of [0, N_SNARKS).
    chunk_idx_range_table: RangeTable<N_SNARKS>,
}

pub struct AssignedBatchDataExport {
    pub num_valid_chunks: AssignedCell<Fr, Fr>,
    pub batch_data_len: AssignedCell<Fr, Fr>,
    pub versioned_hash: Vec<AssignedCell<Fr, Fr>>,
    pub chunk_data_digests: Vec<Vec<AssignedCell<Fr, Fr>>>,
    pub bytes_rlc: AssignedCell<Fr, Fr>,
}

pub struct AssignedBatchDataConfig {
    pub byte: AssignedCell<Fr, Fr>,
    pub accumulator: AssignedCell<Fr, Fr>,
    pub chunk_idx: AssignedCell<Fr, Fr>,
    pub is_boundary: AssignedCell<Fr, Fr>,
    pub boundary_count: AssignedCell<Fr, Fr>,
    pub is_padding: AssignedCell<Fr, Fr>,
    pub bytes_rlc: AssignedCell<Fr, Fr>,
    pub preimage_rlc: AssignedCell<Fr, Fr>,
    pub digest_rlc: AssignedCell<Fr, Fr>,
}

impl<const N_SNARKS: usize> BatchDataConfig<N_SNARKS> {
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        challenge: &Challenges<Expression<Fr>>,
        u8_table: U8Table,
        range_table: RangeTable<N_SNARKS>,
        keccak_table: &KeccakTable,
    ) -> Self {
        let n_rows_metadata = BatchData::<N_SNARKS>::n_rows_metadata();

        let config = Self {
            u8_table,
            chunk_idx_range_table: range_table,
            byte: meta.advice_column(),
            accumulator: meta.advice_column(),
            is_boundary: meta.advice_column(),
            boundary_count: meta.advice_column(),
            chunk_idx: meta.advice_column(),
            is_padding: meta.advice_column(),
            bytes_rlc: meta.advice_column_in(SecondPhase),
            preimage_rlc: meta.advice_column_in(SecondPhase),
            digest_rlc: meta.advice_column_in(SecondPhase),
            data_selector: meta.complex_selector(),
            hash_selector: meta.complex_selector(),
        };

        // TODO: reduce the number of permutation columns
        meta.enable_equality(config.byte);
        meta.enable_equality(config.accumulator);
        meta.enable_equality(config.is_boundary);
        meta.enable_equality(config.boundary_count);
        meta.enable_equality(config.is_padding);
        meta.enable_equality(config.chunk_idx);
        meta.enable_equality(config.bytes_rlc);
        meta.enable_equality(config.preimage_rlc);
        meta.enable_equality(config.digest_rlc);

        let r = challenge.keccak_input();

        meta.lookup("BatchDataConfig (0 < byte < 256)", |meta| {
            let byte_value = meta.query_advice(config.byte, Rotation::cur());
            vec![(byte_value, u8_table.into())]
        });

        meta.lookup(
            "BatchDataConfig (chunk idx transition on boundary)",
            |meta| {
                let is_hash = meta.query_selector(config.hash_selector);
                let is_not_hash = 1.expr() - is_hash;
                let is_padding_next = meta.query_advice(config.is_padding, Rotation::next());
                let is_boundary = meta.query_advice(config.is_boundary, Rotation::cur());
                // if we are in the data section, encounter a boundary and the next row is not a
                // padding row.
                let cond = is_not_hash * is_boundary * (1.expr() - is_padding_next);
                let chunk_idx_curr = meta.query_advice(config.chunk_idx, Rotation::cur());
                let chunk_idx_next = meta.query_advice(config.chunk_idx, Rotation::next());
                // chunk_idx increases by at least 1 and at most N_SNARKS when condition is met.
                vec![(
                    cond * (chunk_idx_next - chunk_idx_curr - 1.expr()),
                    config.chunk_idx_range_table.into(),
                )]
            },
        );

        meta.lookup(
            "BatchDataConfig (chunk_idx for non-padding, data rows in [1..N_SNARKS])",
            |meta| {
                let is_data = meta.query_selector(config.data_selector);
                let is_padding = meta.query_advice(config.is_padding, Rotation::cur());
                let chunk_idx = meta.query_advice(config.chunk_idx, Rotation::cur());
                vec![(
                    is_data * (1.expr() - is_padding) * (chunk_idx - 1.expr()),
                    config.chunk_idx_range_table.into(),
                )]
            },
        );

        meta.create_gate("BatchDataConfig (boolean columns)", |meta| {
            let is_data = meta.query_selector(config.data_selector);
            let is_hash = meta.query_selector(config.hash_selector);

            // is_data is never 1 when is_hash is 1, so we can add these selectors and still have a
            // boolean condition.
            let cond = is_data.clone() + is_hash.clone();

            let is_boundary = meta.query_advice(config.is_boundary, Rotation::cur());
            let is_padding = meta.query_advice(config.is_padding, Rotation::cur());

            vec![
                cond.clone() * is_boundary.clone() * (1.expr() - is_boundary),
                cond * is_padding.clone() * (1.expr() - is_padding),
            ]
        });

        meta.create_gate("BatchDataConfig (transition when boundary)", |meta| {
            let is_data = meta.query_selector(config.data_selector);
            let is_boundary = meta.query_advice(config.is_boundary, Rotation::cur());
            let is_padding_next = meta.query_advice(config.is_padding, Rotation::next());

            let cond = is_data * is_boundary;

            let len_next = meta.query_advice(config.accumulator, Rotation::next());
            let preimage_rlc_next = meta.query_advice(config.preimage_rlc, Rotation::next());
            let byte_next = meta.query_advice(config.byte, Rotation::next());

            let boundary_count_curr = meta.query_advice(config.boundary_count, Rotation::cur());
            let boundary_count_prev = meta.query_advice(config.boundary_count, Rotation::prev());

            vec![
                // if boundary followed by padding, length and preimage_rlc is 0.
                cond.expr() * is_padding_next.expr() * len_next.expr(),
                cond.expr() * is_padding_next.expr() * preimage_rlc_next.expr(),
                // if boundary not followed by padding, length resets to 1, preimage_rlc resets to
                // the byte value.
                cond.expr() * (1.expr() - is_padding_next.expr()) * (len_next.expr() - 1.expr()),
                cond.expr()
                    * (1.expr() - is_padding_next.expr())
                    * (preimage_rlc_next - byte_next.expr()),
                // the boundary count increments, i.e.
                // boundary_count_curr == boundary_count_prev + 1
                cond.expr() * (boundary_count_curr - boundary_count_prev - 1.expr()),
            ]
        });

        meta.create_gate("BatchDataConfig (transition when no boundary)", |meta| {
            let is_data = meta.query_selector(config.data_selector);
            let is_boundary = meta.query_advice(config.is_boundary, Rotation::cur());
            let is_padding = meta.query_advice(config.is_padding, Rotation::cur());

            // in the data section (not padding) when we traverse the same chunk.
            let cond = is_data * (1.expr() - is_padding) * (1.expr() - is_boundary);

            let chunk_idx_curr = meta.query_advice(config.chunk_idx, Rotation::cur());
            let chunk_idx_next = meta.query_advice(config.chunk_idx, Rotation::next());
            let len_curr = meta.query_advice(config.accumulator, Rotation::cur());
            let len_next = meta.query_advice(config.accumulator, Rotation::next());
            let preimage_rlc_curr = meta.query_advice(config.preimage_rlc, Rotation::cur());
            let preimage_rlc_next = meta.query_advice(config.preimage_rlc, Rotation::next());
            let byte_next = meta.query_advice(config.byte, Rotation::next());
            let boundary_count_curr = meta.query_advice(config.boundary_count, Rotation::cur());
            let boundary_count_prev = meta.query_advice(config.boundary_count, Rotation::prev());
            let digest_rlc = meta.query_advice(config.digest_rlc, Rotation::cur());

            vec![
                // chunk idx unchanged.
                cond.expr() * (chunk_idx_next - chunk_idx_curr),
                // length is accumulated.
                cond.expr() * (len_next - len_curr - 1.expr()),
                // preimage rlc is updated.
                cond.expr() * (preimage_rlc_curr * r.expr() + byte_next - preimage_rlc_next),
                // boundary count continues.
                cond.expr() * (boundary_count_curr - boundary_count_prev),
                // digest_rlc is 0.
                cond.expr() * digest_rlc,
            ]
        });

        meta.create_gate("BatchDataConfig (\"chunk data\" section)", |meta| {
            let is_data = meta.query_selector(config.data_selector);
            let is_padding_curr = meta.query_advice(config.is_padding, Rotation::cur());
            let is_padding_next = meta.query_advice(config.is_padding, Rotation::next());
            let diff = is_padding_next - is_padding_curr.expr();
            let byte = meta.query_advice(config.byte, Rotation::cur());
            let chunk_idx = meta.query_advice(config.chunk_idx, Rotation::cur());
            let accumulator = meta.query_advice(config.accumulator, Rotation::cur());
            let preimage_rlc = meta.query_advice(config.preimage_rlc, Rotation::cur());
            let digest_rlc = meta.query_advice(config.digest_rlc, Rotation::cur());
            let boundary_count_curr = meta.query_advice(config.boundary_count, Rotation::cur());
            let boundary_count_prev = meta.query_advice(config.boundary_count, Rotation::prev());
            let bytes_rlc_curr = meta.query_advice(config.bytes_rlc, Rotation::cur());
            let bytes_rlc_prev = meta.query_advice(config.bytes_rlc, Rotation::prev());

            vec![
                // byte, accumulator, digest_rlc, preimage_rlc, chunk_idx iare 0 when padding in
                // the "chunk data" section.
                is_data.expr() * is_padding_curr.expr() * byte.expr(),
                is_data.expr() * is_padding_curr.expr() * accumulator,
                is_data.expr() * is_padding_curr.expr() * digest_rlc,
                is_data.expr() * is_padding_curr.expr() * preimage_rlc,
                is_data.expr() * is_padding_curr.expr() * chunk_idx,
                // diff is 0 or 1, i.e. is_padding transitions from 0 -> 1 only once.
                is_data.expr() * diff.expr() * (1.expr() - diff.expr()),
                // boundary count continues if padding
                is_data.expr()
                    * is_padding_curr.expr()
                    * (boundary_count_curr - boundary_count_prev),
                // bytes rlc is accumulated appropriately
                is_data.expr()
                    * is_padding_curr.expr()
                    * (bytes_rlc_curr.expr() - bytes_rlc_prev.expr()),
                is_data.expr()
                    * (1.expr() - is_padding_curr.expr())
                    * (bytes_rlc_prev * r + byte - bytes_rlc_curr),
            ]
        });

        // lookup metadata and chunk data digests in keccak table.
        meta.lookup_any(
            "BatchDataConfig (metadata/chunk_data/challenge digests in keccak table)",
            |meta| {
                let is_data = meta.query_selector(config.data_selector);
                let is_hash = meta.query_selector(config.hash_selector);
                let is_not_hash = 1.expr() - is_hash;
                let is_boundary = meta.query_advice(config.is_boundary, Rotation::cur());

                // in the "metadata" or "chunk data" section, wherever is_boundary is set.
                let cond = is_not_hash * is_boundary;

                let accumulator = meta.query_advice(config.accumulator, Rotation::cur());
                let preimage_len =
                    is_data.expr() * accumulator + (1.expr() - is_data) * n_rows_metadata.expr();

                [
                    1.expr(),                                                // q_enable
                    1.expr(),                                                // is final
                    meta.query_advice(config.preimage_rlc, Rotation::cur()), // input RLC
                    preimage_len,                                            // input len
                    meta.query_advice(config.digest_rlc, Rotation::cur()),   // output RLC
                ]
                .into_iter()
                .zip_eq(keccak_table.table_exprs(meta))
                .map(|(value, table)| (cond.expr() * value, table))
                .collect()
            },
        );

        // lookup chunk data digests in the "digest rlc section" of BatchDataConfig.
        meta.lookup_any(
            "BatchDataConfig (chunk data digests in BatchDataConfig \"hash section\")",
            |meta| {
                let is_data = meta.query_selector(config.data_selector);
                let is_boundary = meta.query_advice(config.is_boundary, Rotation::cur());

                // in the "chunk data" section when we encounter a chunk boundary
                let cond = is_data * is_boundary;

                let hash_section_table = vec![
                    meta.query_selector(config.hash_selector),
                    meta.query_advice(config.chunk_idx, Rotation::cur()),
                    meta.query_advice(config.accumulator, Rotation::cur()),
                    meta.query_advice(config.digest_rlc, Rotation::cur()),
                ];
                [
                    1.expr(),                                               // hash section
                    meta.query_advice(config.chunk_idx, Rotation::cur()),   // chunk idx
                    meta.query_advice(config.accumulator, Rotation::cur()), // chunk len
                    meta.query_advice(config.digest_rlc, Rotation::cur()),  // digest rlc
                ]
                .into_iter()
                .zip(hash_section_table)
                .map(|(value, table)| (cond.expr() * value, table))
                .collect()
            },
        );

        // lookup challenge digest in keccak table.
        meta.lookup_any(
            "BatchDataConfig (metadata/chunk_data/challenge digests in keccak table)",
            |meta| {
                let is_hash = meta.query_selector(config.hash_selector);
                let is_boundary = meta.query_advice(config.is_boundary, Rotation::cur());

                // when is_boundary is set in the "digest RLC" section.
                // this is also the last row of the "digest RLC" section.
                let cond = is_hash * is_boundary;

                // - metadata_digest: 32 bytes
                // - chunk[i].chunk_data_digest: 32 bytes each
                // - versioned_hash: 32 bytes
                let preimage_len = 32.expr() * (N_SNARKS + 1 + 1).expr();

                [
                    1.expr(),                                                // q_enable
                    1.expr(),                                                // is final
                    meta.query_advice(config.preimage_rlc, Rotation::cur()), // input rlc
                    preimage_len,                                            // input len
                    meta.query_advice(config.digest_rlc, Rotation::cur()),   // output rlc
                ]
                .into_iter()
                .zip_eq(keccak_table.table_exprs(meta))
                .map(|(value, table)| (cond.expr() * value, table))
                .collect()
            },
        );

        log::trace!("meta degree: {}", meta.degree());
        log::trace!(
            "meta degree with lookups: {}",
            meta.clone().chunk_lookups().degree(),
        );

        assert!(meta.degree() <= 5);

        config
    }

    #[allow(clippy::too_many_arguments)]
    pub fn assign(
        &self,
        layouter: &mut impl Layouter<Fr>,
        challenge_value: Challenges<Value<Fr>>,
        rlc_config: &RlcConfig,
        // The chunks_are_padding assigned cells are exports from the conditional constraints in
        // `core.rs`. Since these are already constrained, we can just use them as is.
        chunks_are_padding: &[AssignedCell<Fr, Fr>],
        batch_data: &BatchData<N_SNARKS>,
        versioned_hash: H256,
        barycentric_assignments: &[CRTInteger<Fr>],
    ) -> Result<AssignedBatchDataExport, Error> {
        self.load_range_tables(layouter)?;

        let assigned_rows = layouter.assign_region(
            || "BatchData rows",
            |mut region| self.assign_rows(&mut region, challenge_value, batch_data, versioned_hash),
        )?;

        layouter.assign_region(
            || "BatchData internal checks",
            |mut region| {
                self.assign_internal_checks(
                    &mut region,
                    challenge_value,
                    rlc_config,
                    chunks_are_padding,
                    barycentric_assignments,
                    &assigned_rows,
                )
            },
        )
    }

    pub fn load_range_tables(&self, layouter: &mut impl Layouter<Fr>) -> Result<(), Error> {
        self.u8_table.load(layouter)?;
        self.chunk_idx_range_table.load(layouter)
    }

    pub fn assign_rows(
        &self,
        region: &mut Region<Fr>,
        challenge_value: Challenges<Value<Fr>>,
        batch_data: &BatchData<N_SNARKS>,
        versioned_hash: H256,
    ) -> Result<Vec<AssignedBatchDataConfig>, Error> {
        let n_rows_data = BatchData::<N_SNARKS>::n_rows_data();
        let n_rows_metadata = BatchData::<N_SNARKS>::n_rows_metadata();
        let n_rows_digest_rlc = BatchData::<N_SNARKS>::n_rows_digest_rlc();
        let n_rows_total = BatchData::<N_SNARKS>::n_rows();

        let rows = batch_data.to_rows(versioned_hash, challenge_value);
        assert_eq!(rows.len(), n_rows_total);

        // enable data selector
        for offset in n_rows_metadata..n_rows_metadata + n_rows_data {
            self.data_selector.enable(region, offset)?;
        }

        // enable hash selector
        for offset in
            n_rows_metadata + n_rows_data..n_rows_metadata + n_rows_data + n_rows_digest_rlc
        {
            self.hash_selector.enable(region, offset)?;
        }

        let mut assigned_rows = Vec::with_capacity(n_rows_total);
        let mut count = 0u64;
        let mut bytes_rlc_acc = Value::known(Fr::zero());
        for (i, row) in rows.iter().enumerate() {
            if !row.is_padding {
                bytes_rlc_acc = bytes_rlc_acc * challenge_value.keccak_input()
                    + Value::known(Fr::from(row.byte as u64));
            }
            let byte = region.assign_advice(
                || "byte",
                self.byte,
                i,
                || Value::known(Fr::from(row.byte as u64)),
            )?;
            let accumulator = region.assign_advice(
                || "accumulator",
                self.accumulator,
                i,
                || Value::known(Fr::from(row.accumulator)),
            )?;
            let chunk_idx = region.assign_advice(
                || "chunk_idx",
                self.chunk_idx,
                i,
                || Value::known(Fr::from(row.chunk_idx)),
            )?;
            let is_boundary = region.assign_advice(
                || "is_boundary",
                self.is_boundary,
                i,
                || Value::known(Fr::from(row.is_boundary as u64)),
            )?;
            let bcount = if (n_rows_metadata..n_rows_metadata + n_rows_data).contains(&i) {
                count += row.is_boundary as u64;
                count
            } else {
                0
            };
            let boundary_count = region.assign_advice(
                || "boundary_count",
                self.boundary_count,
                i,
                || Value::known(Fr::from(bcount)),
            )?;
            let is_padding = region.assign_advice(
                || "is_padding",
                self.is_padding,
                i,
                || Value::known(Fr::from(row.is_padding as u64)),
            )?;
            let preimage_rlc = region.assign_advice(
                || "preimage_rlc",
                self.preimage_rlc,
                i,
                || row.preimage_rlc,
            )?;
            let digest_rlc =
                region.assign_advice(|| "digest_rlc", self.digest_rlc, i, || row.digest_rlc)?;
            let bytes_rlc = region.assign_advice(
                || "bytes_rlc",
                self.bytes_rlc,
                i,
                || {
                    if i < n_rows_metadata + n_rows_data {
                        bytes_rlc_acc
                    } else {
                        Value::known(Fr::zero())
                    }
                },
            )?;
            assigned_rows.push(AssignedBatchDataConfig {
                byte,
                accumulator,
                chunk_idx,
                is_boundary,
                boundary_count,
                is_padding,
                bytes_rlc,
                preimage_rlc,
                digest_rlc,
            });
        }
        Ok(assigned_rows)
    }

    pub fn assign_internal_checks(
        &self,
        region: &mut Region<Fr>,
        challenge_value: Challenges<Value<Fr>>,
        rlc_config: &RlcConfig,
        // The chunks_are_padding assigned cells are exports from the conditional constraints in
        // `core.rs`. Since these are already constrained, we can just use them as is.
        chunks_are_padding: &[AssignedCell<Fr, Fr>],
        barycentric_assignments: &[CRTInteger<Fr>],
        assigned_rows: &[AssignedBatchDataConfig],
    ) -> Result<AssignedBatchDataExport, Error> {
        let n_rows_metadata = BatchData::<N_SNARKS>::n_rows_metadata();
        let n_rows_digest_rlc = BatchData::<N_SNARKS>::n_rows_digest_rlc();
        let n_rows_data = BatchData::<N_SNARKS>::n_rows_data();

        rlc_config.init(region)?;
        let mut rlc_config_offset = 0;

        // load some constants that we will use later.
        let zero = {
            let zero = rlc_config.load_private(region, &Fr::zero(), &mut rlc_config_offset)?;
            let zero_cell = rlc_config.zero_cell(zero.cell().region_index);
            region.constrain_equal(zero.cell(), zero_cell)?;
            zero
        };
        let one = {
            let one = rlc_config.load_private(region, &Fr::one(), &mut rlc_config_offset)?;
            let one_cell = rlc_config.one_cell(one.cell().region_index);
            region.constrain_equal(one.cell(), one_cell)?;
            one
        };
        let four = {
            let four = rlc_config.load_private(region, &Fr::from(4), &mut rlc_config_offset)?;
            let four_cell = rlc_config.four_cell(four.cell().region_index);
            region.constrain_equal(four.cell(), four_cell)?;
            four
        };
        let fixed_chunk_indices = {
            let mut fixed_chunk_indices = vec![one.clone()];
            for i in 2..=N_SNARKS {
                let i_cell =
                    rlc_config.load_private(region, &Fr::from(i as u64), &mut rlc_config_offset)?;
                // TODO: look into this....
                let i_fixed_cell =
                    rlc_config.fixed_up_to_max_agg_snarks_cell(i_cell.cell().region_index, i);
                region.constrain_equal(i_cell.cell(), i_fixed_cell)?;
                fixed_chunk_indices.push(i_cell);
            }
            fixed_chunk_indices
        };
        let two = fixed_chunk_indices.get(1).expect("N_SNARKS >= 2");
        let n_snarks = fixed_chunk_indices.last().expect("N_SNARKS >= 2");
        let pows_of_256 = {
            let mut pows_of_256 = vec![one.clone()];
            for (exponent, pow_of_256) in (1..=POWS_OF_256).zip_eq(
                std::iter::successors(Some(Fr::from(256)), |n| Some(n * Fr::from(256)))
                    .take(POWS_OF_256),
            ) {
                let pow_cell =
                    rlc_config.load_private(region, &pow_of_256, &mut rlc_config_offset)?;
                let fixed_pow_cell = rlc_config
                    .pow_of_two_hundred_and_fifty_six_cell(pow_cell.cell().region_index, exponent);
                region.constrain_equal(pow_cell.cell(), fixed_pow_cell)?;
                pows_of_256.push(pow_cell);
            }
            pows_of_256
        };
        let two_fifty_six = pows_of_256[1].clone();

        // read randomness challenges for RLC computations.
        let r_keccak =
            rlc_config.read_challenge1(region, challenge_value, &mut rlc_config_offset)?;
        let r_evm = rlc_config.read_challenge2(region, challenge_value, &mut rlc_config_offset)?;
        let r32 = {
            let r2 = rlc_config.mul(region, &r_keccak, &r_keccak, &mut rlc_config_offset)?;
            let r4 = rlc_config.mul(region, &r2, &r2, &mut rlc_config_offset)?;
            let r8 = rlc_config.mul(region, &r4, &r4, &mut rlc_config_offset)?;
            let r16 = rlc_config.mul(region, &r8, &r8, &mut rlc_config_offset)?;
            rlc_config.mul(region, &r16, &r16, &mut rlc_config_offset)?
        };

        // load cells representing the keccak digest of empty bytes.
        let mut empty_digest_cells = Vec::with_capacity(N_BYTES_U256);
        for (i, &byte) in keccak256([]).iter().enumerate() {
            let cell =
                rlc_config.load_private(region, &Fr::from(byte as u64), &mut rlc_config_offset)?;
            let fixed_cell = rlc_config.empty_keccak_cell_i(cell.cell().region_index, i);
            region.constrain_equal(cell.cell(), fixed_cell)?;
            empty_digest_cells.push(cell);
        }
        let empty_digest_evm_rlc =
            rlc_config.rlc(region, &empty_digest_cells, &r_evm, &mut rlc_config_offset)?;

        ////////////////////////////////////////////////////////////////////////////////
        /////////////////////////////// NUM_VALID_CHUNKS ///////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////

        let rows = assigned_rows.iter().take(2).collect::<Vec<_>>();
        let (byte_hi, byte_lo, lc1, lc2) = (
            &rows[0].byte,
            &rows[1].byte,
            &rows[0].accumulator,
            &rows[1].accumulator,
        );

        // the linear combination starts with the most-significant byte.
        region.constrain_equal(byte_hi.cell(), lc1.cell())?;

        // do the linear combination.
        let num_valid_chunks =
            rlc_config.mul_add(region, lc1, &two_fifty_six, byte_lo, &mut rlc_config_offset)?;
        region.constrain_equal(num_valid_chunks.cell(), lc2.cell())?;

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////// CHUNK_SIZE //////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////

        let mut num_nonempty_chunks = zero.clone();
        let mut is_empty_chunks = Vec::with_capacity(N_SNARKS);
        let mut chunk_sizes = Vec::with_capacity(N_SNARKS);
        // init: batch_data_len = 4 * N_SNARKS + 2 (metadata).
        let mut batch_data_len =
            rlc_config.mul_add(region, &four, n_snarks, two, &mut rlc_config_offset)?;
        for (i, is_padded_chunk) in chunks_are_padding.iter().enumerate() {
            let rows = assigned_rows
                .iter()
                .skip(2 + 4 * i)
                .take(4)
                .collect::<Vec<_>>();
            let (byte0, byte1, byte2, byte3) =
                (&rows[0].byte, &rows[1].byte, &rows[2].byte, &rows[3].byte);
            let (acc0, acc1, acc2, acc3) = (
                &rows[0].accumulator,
                &rows[1].accumulator,
                &rows[2].accumulator,
                &rows[3].accumulator,
            );

            // the linear combination starts with the most-significant byte.
            region.constrain_equal(byte0.cell(), acc0.cell())?;

            // do the linear combination.
            let lc =
                rlc_config.mul_add(region, acc0, &two_fifty_six, byte1, &mut rlc_config_offset)?;
            region.constrain_equal(lc.cell(), acc1.cell())?;
            let lc =
                rlc_config.mul_add(region, acc1, &two_fifty_six, byte2, &mut rlc_config_offset)?;
            region.constrain_equal(lc.cell(), acc2.cell())?;
            let chunk_size =
                rlc_config.mul_add(region, acc2, &two_fifty_six, byte3, &mut rlc_config_offset)?;
            region.constrain_equal(chunk_size.cell(), acc3.cell())?;

            // if the chunk is a padded chunk, its size must be set to 0.
            rlc_config.conditional_enforce_equal(
                region,
                &chunk_size,
                &zero,
                is_padded_chunk,
                &mut rlc_config_offset,
            )?;

            let is_empty_chunk = rlc_config.is_zero(region, &chunk_size, &mut rlc_config_offset)?;
            let is_nonempty_chunk =
                rlc_config.not(region, &is_empty_chunk, &mut rlc_config_offset)?;
            num_nonempty_chunks = rlc_config.add(
                region,
                &is_nonempty_chunk,
                &num_nonempty_chunks,
                &mut rlc_config_offset,
            )?;
            batch_data_len =
                rlc_config.add(region, &batch_data_len, &chunk_size, &mut rlc_config_offset)?;

            is_empty_chunks.push(is_empty_chunk);
            chunk_sizes.push(chunk_size);
        }
        let all_chunks_empty =
            rlc_config.is_zero(region, &num_nonempty_chunks, &mut rlc_config_offset)?;
        let not_all_chunks_empty =
            rlc_config.not(region, &all_chunks_empty, &mut rlc_config_offset)?;

        // constrain preimage_rlc column
        let metadata_rows = &assigned_rows[..n_rows_metadata];
        region.constrain_equal(
            metadata_rows[0].byte.cell(),
            metadata_rows[0].preimage_rlc.cell(),
        )?;
        for (i, row) in metadata_rows.iter().enumerate().skip(1) {
            let preimage_rlc = rlc_config.mul_add(
                region,
                &metadata_rows[i - 1].preimage_rlc,
                &r_keccak,
                &row.byte,
                &mut rlc_config_offset,
            )?;
            region.constrain_equal(preimage_rlc.cell(), row.preimage_rlc.cell())?;
        }

        // these columns are always 0 in the metadata section.
        for row in metadata_rows.iter() {
            let cells =
                [&row.chunk_idx, &row.boundary_count, &row.is_padding].map(AssignedCell::cell);

            for cell in cells {
                region.constrain_equal(cell, zero.cell())?;
            }
        }

        // in the metadata section, these columns are 0 except (possibly) on the last row.
        for row in metadata_rows.iter().take(n_rows_metadata - 1) {
            let cells = [&row.is_boundary, &row.digest_rlc].map(AssignedCell::cell);

            for cell in cells {
                region.constrain_equal(cell, zero.cell())?;
            }
        }

        // in the final row of the metadata section, boundary is 1. note that this triggers a keccak
        // lookup which constrains digest_rlc.
        region.constrain_equal(
            metadata_rows[n_rows_metadata - 1].is_boundary.cell(),
            one.cell(),
        )?;

        // also check that the preimage_rlc at the last row of "metadata" section is equal to the
        // bytes_rlc at that row. This value is later used in the custom gate in the "chunk data"
        // section to compute the running accumulator bytes_rlc.
        region.constrain_equal(
            metadata_rows[n_rows_metadata - 1].preimage_rlc.cell(),
            metadata_rows[n_rows_metadata - 1].bytes_rlc.cell(),
        )?;

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////// CHUNK_DATA //////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////

        // the first data row has a length (accumulator) of 1. But in the special case that
        // there are no non-empty chunks, this will be 0 and must also be a padding row.
        let rows = assigned_rows
            .iter()
            .skip(n_rows_metadata)
            .take(n_rows_data)
            .collect::<Vec<_>>();
        rlc_config.conditional_enforce_equal(
            region,
            &rows[0].accumulator,
            &one,
            &not_all_chunks_empty,
            &mut rlc_config_offset,
        )?;
        rlc_config.conditional_enforce_equal(
            region,
            &rows[0].is_padding,
            &zero,
            &not_all_chunks_empty,
            &mut rlc_config_offset,
        )?;
        rlc_config.conditional_enforce_equal(
            region,
            &rows[0].accumulator,
            &zero,
            &all_chunks_empty,
            &mut rlc_config_offset,
        )?;
        rlc_config.conditional_enforce_equal(
            region,
            &rows[0].is_padding,
            &one,
            &all_chunks_empty,
            &mut rlc_config_offset,
        )?;

        // get the boundary count at the end of the "chunk data" section, and equate it to
        // the number of non-empty chunks in the batch.
        region.constrain_equal(
            rows.last().unwrap().boundary_count.cell(),
            num_nonempty_chunks.cell(),
        )?;

        ////////////////////////////////////////////////////////////////////////////////
        ////////////////////////////////// DIGEST RLC //////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////

        let rows = assigned_rows
            .iter()
            .skip(n_rows_metadata + n_rows_data)
            .take(n_rows_digest_rlc)
            .collect::<Vec<_>>();

        // rows have chunk_idx set from 0 (metadata) -> N_SNARKS.
        region.constrain_equal(rows[0].chunk_idx.cell(), zero.cell())?;
        for (row, fixed_chunk_idx) in rows
            .iter()
            .skip(1)
            .take(N_SNARKS)
            .zip_eq(fixed_chunk_indices.iter())
        {
            region.constrain_equal(row.chunk_idx.cell(), fixed_chunk_idx.cell())?;
        }

        let challenge_digest_preimage_rlc_specified = &rows.last().unwrap().preimage_rlc;
        let challenge_digest_rlc_specified = &rows.last().unwrap().digest_rlc;
        let versioned_hash_rlc = &rows.get(n_rows_digest_rlc - 2).unwrap().digest_rlc;

        // ensure that on the last row of this section the is_boundary is turned on
        // which would enable the keccak table lookup for challenge_digest
        region.constrain_equal(rows.last().unwrap().is_boundary.cell(), one.cell())?;

        let metadata_digest_rlc_computed =
            &assigned_rows.get(n_rows_metadata - 1).unwrap().digest_rlc;
        let metadata_digest_rlc_specified = &rows.first().unwrap().digest_rlc;
        region.constrain_equal(
            metadata_digest_rlc_computed.cell(),
            metadata_digest_rlc_specified.cell(),
        )?;

        // if the chunk is a padded chunk, then its chunk data digest should be the
        // same as the previous chunk's data digest.
        //
        // Also, we know that the first chunk is valid. So we can just start the check from
        // the second chunk's data digest.
        region.constrain_equal(chunks_are_padding[0].cell(), zero.cell())?;
        for i in 1..N_SNARKS {
            // Note that in `rows`, the first row is the metadata row (hence anyway skip
            // it). That's why we have a +1.
            rlc_config.conditional_enforce_equal(
                region,
                &rows[i + 1].digest_rlc,
                &rows[i].digest_rlc,
                &chunks_are_padding[i],
                &mut rlc_config_offset,
            )?;
        }

        let mut chunk_digest_evm_rlcs = Vec::with_capacity(N_SNARKS);
        for (((row, chunk_size_decoded), is_empty), is_padded_chunk) in rows
            .iter()
            .skip(1)
            .take(N_SNARKS)
            .zip_eq(chunk_sizes)
            .zip_eq(is_empty_chunks)
            .zip_eq(chunks_are_padding)
        {
            // if the chunk is a valid chunk (i.e. not padded chunk), but is empty (i.e. no
            // L2 transactions), then the chunk's data digest should be the empty keccak
            // digest.
            let is_valid = rlc_config.not(region, is_padded_chunk, &mut rlc_config_offset)?;
            let is_valid_empty =
                rlc_config.mul(region, &is_valid, &is_empty, &mut rlc_config_offset)?;
            rlc_config.conditional_enforce_equal(
                region,
                &row.digest_rlc,
                &empty_digest_evm_rlc,
                &is_valid_empty,
                &mut rlc_config_offset,
            )?;

            // constrain chunk size specified here against decoded in metadata.
            region.constrain_equal(row.accumulator.cell(), chunk_size_decoded.cell())?;

            chunk_digest_evm_rlcs.push(&row.digest_rlc);
        }

        ////////////////////////////////////////////////////////////////////////////////
        ///////////////////////////////// DIGEST BYTES /////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////

        let mut challenge_digest_preimage_keccak_rlc = zero.clone();
        let rows = assigned_rows
            .iter()
            .skip(n_rows_metadata + n_rows_data + n_rows_digest_rlc)
            .take(BatchData::<N_SNARKS>::n_rows_digest_bytes())
            .collect::<Vec<_>>();
        for (i, digest_rlc_specified) in std::iter::once(metadata_digest_rlc_specified)
            .chain(chunk_digest_evm_rlcs)
            .chain(std::iter::once(versioned_hash_rlc))
            .chain(std::iter::once(challenge_digest_rlc_specified))
            .enumerate()
        {
            let digest_rows = rows
                .iter()
                .skip(N_BYTES_U256 * i)
                .take(N_BYTES_U256)
                .collect::<Vec<_>>();
            let digest_bytes = digest_rows
                .iter()
                .map(|row| row.byte.clone())
                .collect::<Vec<_>>();
            let digest_rlc_computed =
                rlc_config.rlc(region, &digest_bytes, &r_evm, &mut rlc_config_offset)?;
            region.constrain_equal(digest_rlc_computed.cell(), digest_rlc_specified.cell())?;

            // compute the keccak input RLC:
            // we do this only for the metadata and chunks, not for the blob row itself.
            if i < N_SNARKS + 1 + 1 {
                let digest_keccak_rlc =
                    rlc_config.rlc(region, &digest_bytes, &r_keccak, &mut rlc_config_offset)?;
                challenge_digest_preimage_keccak_rlc = rlc_config.mul_add(
                    region,
                    &challenge_digest_preimage_keccak_rlc,
                    &r32,
                    &digest_keccak_rlc,
                    &mut rlc_config_offset,
                )?;
            }
        }
        region.constrain_equal(
            challenge_digest_preimage_keccak_rlc.cell(),
            challenge_digest_preimage_rlc_specified.cell(),
        )?;

        ////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////// EXPORT ////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////

        let mut chunk_data_digests = Vec::with_capacity(N_SNARKS);
        let chunk_data_digests_bytes = assigned_rows
            .iter()
            .skip(n_rows_metadata + n_rows_data + n_rows_digest_rlc + N_BYTES_U256)
            .take(N_SNARKS * N_BYTES_U256)
            .map(|row| row.byte.clone())
            .collect::<Vec<_>>();
        for chunk in chunk_data_digests_bytes.chunks_exact(N_BYTES_U256) {
            chunk_data_digests.push(chunk.to_vec());
        }
        let challenge_digest = assigned_rows
            .iter()
            .rev()
            .take(N_BYTES_U256)
            .map(|row| row.byte.clone())
            .collect::<Vec<AssignedCell<Fr, Fr>>>();
        let export = AssignedBatchDataExport {
            num_valid_chunks,
            batch_data_len,
            versioned_hash: assigned_rows
                .iter()
                .rev()
                .skip(N_BYTES_U256)
                .take(N_BYTES_U256)
                .map(|row| row.byte.clone())
                .rev()
                .collect(),
            chunk_data_digests,
            // bytes rlc is from the last row of the "chunk data" section.
            bytes_rlc: assigned_rows
                .get(n_rows_metadata + n_rows_data - 1)
                .unwrap()
                .bytes_rlc
                .clone(),
        };

        ////////////////////////////////////////////////////////////////////////////////
        //////////////////////////// CHALLENGE DIGEST CHECK ////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////

        assert_eq!(barycentric_assignments.len(), BLOB_WIDTH + 1);
        let challenge_digest_crt = barycentric_assignments
            .get(BLOB_WIDTH)
            .expect("challenge digest CRT");
        let challenge_digest_limb1 = rlc_config.inner_product(
            region,
            &challenge_digest[0..11],
            &pows_of_256,
            &mut rlc_config_offset,
        )?;
        let challenge_digest_limb2 = rlc_config.inner_product(
            region,
            &challenge_digest[11..22],
            &pows_of_256,
            &mut rlc_config_offset,
        )?;
        let challenge_digest_limb3 = rlc_config.inner_product(
            region,
            &challenge_digest[22..32],
            &pows_of_256[0..10],
            &mut rlc_config_offset,
        )?;
        region.constrain_equal(
            challenge_digest_limb1.cell(),
            challenge_digest_crt.truncation.limbs[0].cell(),
        )?;
        region.constrain_equal(
            challenge_digest_limb2.cell(),
            challenge_digest_crt.truncation.limbs[1].cell(),
        )?;
        region.constrain_equal(
            challenge_digest_limb3.cell(),
            challenge_digest_crt.truncation.limbs[2].cell(),
        )?;

        Ok(export)
    }
}

/// Helper struct to generate witness for the Batch Data Config.
#[derive(Clone, Debug)]
pub struct BatchData<const N_SNARKS: usize> {
    /// The number of valid chunks in the batch. This could be any number between:
    /// [1, N_SNARKS]
    pub num_valid_chunks: u16,
    /// The size of each chunk. The chunk size can be zero if:
    /// - The chunk is a padded chunk (not a valid chunk).
    /// - The chunk has no L2 transactions, but only L1 msg txs.
    pub chunk_sizes: [u32; N_SNARKS],
    /// Flattened L2 signed transaction data, for each chunk.
    ///
    /// Note that in BatchData struct, only `num_valid_chunks` number of chunks' bytes are supposed
    /// to be read (for witness generation). For simplicity, the last valid chunk's bytes are
    /// copied over for the padded chunks. The `chunk_data_digest` for padded chunks is the
    /// `chunk_data_digest` of the last valid chunk (from Aggregation Circuit's perspective).
    pub chunk_data: [Vec<u8>; N_SNARKS],
}

impl<const N_SNARKS: usize> BatchData<N_SNARKS> {
    /// For raw batch bytes with metadata, this function segments the byte stream into chunk segments.
    /// Metadata will be removed from the result.
    pub fn segment_with_metadata(batch_bytes_with_metadata: Vec<u8>) -> Vec<Vec<u8>> {
        let n_bytes_metadata = Self::n_rows_metadata();
        let metadata_bytes = batch_bytes_with_metadata
            .clone()
            .into_iter()
            .take(n_bytes_metadata)
            .collect::<Vec<u8>>();
        let batch_bytes = batch_bytes_with_metadata
            .clone()
            .into_iter()
            .skip(n_bytes_metadata)
            .collect::<Vec<u8>>();

        // Decoded batch bytes require segmentation based on chunk length
        let batch_data_len = batch_bytes.len();
        let chunk_lens = metadata_bytes[N_ROWS_NUM_CHUNKS..]
            .chunks(N_ROWS_CHUNK_SIZE)
            .map(|chunk| {
                chunk
                    .iter()
                    .fold(0usize, |acc, &d| acc * 256usize + d as usize)
            })
            .collect::<Vec<usize>>();

        // length segments sanity check
        let valid_chunks = metadata_bytes
            .iter()
            .take(N_ROWS_NUM_CHUNKS)
            .fold(0usize, |acc, &d| acc * 256usize + d as usize);
        let calculated_len = chunk_lens.iter().take(valid_chunks).sum::<usize>();
        assert_eq!(
            batch_data_len, calculated_len,
            "chunk segmentation len must add up to the correct value"
        );

        // reconstruct segments
        let mut segmented_batch_data: Vec<Vec<u8>> = Vec::new();
        let mut offset: usize = 0;
        let mut segment: usize = 0;
        while offset < batch_data_len {
            segmented_batch_data.push(
                batch_bytes
                    .clone()
                    .into_iter()
                    .skip(offset)
                    .take(chunk_lens[segment])
                    .collect::<Vec<u8>>(),
            );

            offset += chunk_lens[segment];
            segment += 1;
        }

        segmented_batch_data
    }
}

impl<const N_SNARKS: usize> From<&BatchHash<N_SNARKS>> for BatchData<N_SNARKS> {
    fn from(batch_hash: &BatchHash<N_SNARKS>) -> Self {
        Self::new(
            batch_hash.number_of_valid_chunks,
            &batch_hash.chunks_with_padding,
        )
    }
}

// If the chunk data is represented as a vector of u8's this implementation converts data from
// dynamic number of chunks into BatchData.
impl<const N_SNARKS: usize> From<&Vec<Vec<u8>>> for BatchData<N_SNARKS> {
    fn from(chunks: &Vec<Vec<u8>>) -> Self {
        let num_valid_chunks = chunks.len();
        assert!(num_valid_chunks > 0);
        assert!(num_valid_chunks <= N_SNARKS);

        let chunk_sizes: [u32; N_SNARKS] = chunks
            .iter()
            .map(|chunk| chunk.len() as u32)
            .chain(repeat(0))
            .take(N_SNARKS)
            .collect::<Vec<_>>()
            .try_into()
            .expect("we have N_SNARKS chunks");
        assert!(chunk_sizes.iter().sum::<u32>() <= Self::n_rows_data().try_into().unwrap());

        let last_chunk_data = chunks.last().expect("last chunk exists");
        let chunk_data = chunks
            .iter()
            .chain(repeat(last_chunk_data))
            .take(N_SNARKS)
            .cloned()
            .collect::<Vec<_>>()
            .try_into()
            .expect("we have N_SNARKS chunks");

        Self {
            num_valid_chunks: num_valid_chunks.try_into().unwrap(),
            chunk_sizes,
            chunk_data,
        }
    }
}

impl<const N_SNARKS: usize> Default for BatchData<N_SNARKS> {
    fn default() -> Self {
        // default value corresponds to a batch with 1 chunk with no transactions
        Self::from(&vec![vec![]])
    }
}

impl<const N_SNARKS: usize> BatchData<N_SNARKS> {
    /// The number of rows in Blob Data config's layout to represent the "digest rlc" section.
    /// - metadata digest RLC (1 row)
    /// - chunk_digests RLC for each chunk (MAX_AGG_SNARKS rows)
    /// - blob versioned hash RLC (1 row)
    /// - challenge digest RLC (1 row)
    pub const fn n_rows_digest_rlc() -> usize {
        1 + N_SNARKS + 1 + 1
    }

    /// The number of rows in Blob Data config's layout to represent the "digest bytes" section.
    pub const fn n_rows_digest_bytes() -> usize {
        Self::n_rows_digest_rlc() * N_BYTES_U256
    }

    /// The number of rows to encode the size of each chunk in a batch, in the Blob Data config.
    /// chunk_size is u32, we use 4 bytes/rows.
    const fn n_rows_chunk_sizes() -> usize {
        N_SNARKS * N_ROWS_CHUNK_SIZE
    }

    /// The total number of rows in "digest rlc" and "digest bytes" sections.
    const fn n_rows_digest() -> usize {
        Self::n_rows_digest_rlc() + Self::n_rows_digest_bytes()
    }

    /// The number of rows in Blob Data config's layout to represent the "blob metadata" section.
    pub const fn n_rows_metadata() -> usize {
        N_ROWS_NUM_CHUNKS + Self::n_rows_chunk_sizes()
    }

    /// The number of rows in Blob Data config's layout to represent the "chunk data" section.
    pub const fn n_rows_data() -> usize {
        N_BATCH_BYTES - Self::n_rows_metadata()
    }

    /// The total number of rows used in Blob Data config's layout.
    pub const fn n_rows() -> usize {
        N_BATCH_BYTES + Self::n_rows_digest()
    }

    /// Construct BatchData from chunks
    pub fn new(num_valid_chunks: usize, chunks_with_padding: &[ChunkInfo]) -> Self {
        assert!(num_valid_chunks > 0);
        assert!(num_valid_chunks <= N_SNARKS);

        // padded chunk has 0 size, valid chunk's size is the number of bytes consumed by the
        // flattened data from signed L2 transactions.
        let chunk_sizes: [u32; N_SNARKS] = chunks_with_padding
            .iter()
            .map(|chunk| {
                if chunk.is_padding {
                    0
                } else {
                    chunk.tx_bytes.len() as u32
                }
            })
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();

        if chunk_sizes.iter().sum::<u32>() > Self::n_rows_data() as u32 {
            panic!(
                "invalid chunk_sizes {}, n_rows_data {}",
                chunk_sizes.iter().sum::<u32>(),
                Self::n_rows_data()
            )
        }

        // chunk data of the "last valid chunk" is repeated over the padded chunks for simplicity
        // in calculating chunk_data_digest for those padded chunks. However, for the "chunk data"
        // section rows (self.to_data_rows()) we only consider `num_valid_chunks` chunks.
        let chunk_data = chunks_with_padding
            .iter()
            .map(|chunk| chunk.tx_bytes.to_vec())
            .collect::<Vec<Vec<u8>>>()
            .try_into()
            .unwrap();

        Self {
            num_valid_chunks: num_valid_chunks as u16,
            chunk_sizes,
            chunk_data,
        }
    }

    /// Get the preimage of the challenge digest.
    pub(crate) fn get_challenge_digest_preimage(&self, versioned_hash: H256) -> Vec<u8> {
        let metadata_digest = keccak256(self.to_metadata_bytes());
        let chunk_digests = self.chunk_data.iter().map(keccak256);

        // preimage =
        //     metadata_digest ||
        //     chunk[0].chunk_data_digest || ...
        //     chunk[N_SNARKS-1].chunk_data_digest ||
        //     blob_versioned_hash
        //
        // where chunk_data_digest for a padded chunk is set equal to the "last valid chunk"'s
        // chunk_data_digest.
        metadata_digest
            .into_iter()
            .chain(chunk_digests.flatten())
            .chain(versioned_hash.to_fixed_bytes())
            .collect::<Vec<_>>()
    }

    /// Compute the challenge digest from blob bytes.
    pub(crate) fn get_challenge_digest(&self, versioned_hash: H256) -> U256 {
        let challenge_digest = keccak256(self.get_challenge_digest_preimage(versioned_hash));
        U256::from_big_endian(&challenge_digest)
    }

    /// Get the batch data bytes that will be populated in BatchDataConfig.
    pub fn get_batch_data_bytes(&self) -> Vec<u8> {
        let metadata_bytes = self.to_metadata_bytes();
        metadata_bytes
            .iter()
            .chain(
                self.chunk_data
                    .iter()
                    .take(self.num_valid_chunks as usize)
                    .flatten(),
            )
            .cloned()
            .collect()
    }

    /// Get the list of preimages that need to go through the keccak hashing function, and
    /// eventually required to be checked for the consistency of blob's metadata, its chunks' bytes
    /// and the final blob preimage.
    pub fn preimages(&self, versioned_hash: H256) -> Vec<Vec<u8>> {
        let mut preimages = Vec::with_capacity(2 + N_SNARKS);

        // metadata
        preimages.push(self.to_metadata_bytes());

        // each valid chunk's data
        for chunk in self.chunk_data.iter().take(self.num_valid_chunks as usize) {
            preimages.push(chunk.to_vec());
        }

        // preimage for challenge digest
        preimages.push(self.get_challenge_digest_preimage(versioned_hash));

        preimages
    }

    /// Get the witness rows for assignment to the BlobDataConfig.
    fn to_rows(
        &self,
        versioned_hash: H256,
        challenge: Challenges<Value<Fr>>,
    ) -> Vec<BatchDataRow<Fr>> {
        let metadata_rows = self.to_metadata_rows(challenge);
        assert_eq!(metadata_rows.len(), Self::n_rows_metadata());

        let data_rows = self.to_data_rows(challenge);
        assert_eq!(data_rows.len(), Self::n_rows_data());

        let digest_rows = self.to_digest_rows(versioned_hash, challenge);
        assert_eq!(digest_rows.len(), Self::n_rows_digest());

        metadata_rows
            .into_iter()
            .chain(data_rows)
            .chain(digest_rows)
            .collect::<Vec<BatchDataRow<Fr>>>()
    }

    /// Get the blob bytes that encode the batch's metadata.
    ///
    /// metadata_bytes =
    ///     be_bytes(num_valid_chunks) ||
    ///     be_bytes(chunks[0].chunk_size) || ...
    ///     be_bytes(chunks[N_SNARKS-1].chunk_size)
    ///
    /// where:
    /// - chunk_size of a padded chunk is 0
    /// - num_valid_chunks is u16
    /// - each chunk_size is u32
    fn to_metadata_bytes(&self) -> Vec<u8> {
        self.num_valid_chunks
            .to_be_bytes()
            .into_iter()
            .chain(
                self.chunk_sizes
                    .iter()
                    .flat_map(|chunk_size| chunk_size.to_be_bytes()),
            )
            .collect()
    }

    /// Get the witness rows for the "metadata" section of Blob data config.
    fn to_metadata_rows(&self, challenge: Challenges<Value<Fr>>) -> Vec<BatchDataRow<Fr>> {
        // metadata bytes.
        let bytes = self.to_metadata_bytes();

        // accumulators represent the running linear combination of bytes.
        let accumulators_iter = self
            .num_valid_chunks
            .to_be_bytes()
            .into_iter()
            .scan(0u64, |acc, x| {
                *acc = *acc * 256 + (x as u64);
                Some(*acc)
            })
            .chain(self.chunk_sizes.into_iter().flat_map(|chunk_size| {
                chunk_size.to_be_bytes().into_iter().scan(0u64, |acc, x| {
                    *acc = *acc * 256 + (x as u64);
                    Some(*acc)
                })
            }));

        // digest_rlc is set only for the last row in the "metadata" section, and it denotes the
        // RLC of the metadata_digest bytes.
        let digest_rlc_iter = {
            let digest = keccak256(&bytes);
            let digest_rlc = digest.iter().fold(Value::known(Fr::zero()), |acc, &x| {
                acc * challenge.evm_word() + Value::known(Fr::from(x as u64))
            });
            repeat(Value::known(Fr::zero()))
                .take(Self::n_rows_metadata() - 1)
                .chain(once(digest_rlc))
        };

        // preimage_rlc is the running RLC over bytes in the "metadata" section.
        let preimage_rlc_iter = bytes.iter().scan(Value::known(Fr::zero()), |acc, &x| {
            *acc = *acc * challenge.keccak_input() + Value::known(Fr::from(x as u64));
            Some(*acc)
        });

        bytes
            .iter()
            .zip_eq(accumulators_iter)
            .zip_eq(preimage_rlc_iter)
            .zip_eq(digest_rlc_iter)
            .enumerate()
            .map(
                |(i, (((&byte, accumulator), preimage_rlc), digest_rlc))| BatchDataRow {
                    byte,
                    accumulator,
                    preimage_rlc,
                    digest_rlc,
                    // we set boundary on the last row of the "metadata" section to enable a lookup
                    // to the keccak table.
                    is_boundary: i == bytes.len() - 1,
                    ..Default::default()
                },
            )
            .collect()
    }

    /// Get the witness rows for the "chunk data" section of Blob data config.
    fn to_data_rows(&self, challenge: Challenges<Value<Fr>>) -> Vec<BatchDataRow<Fr>> {
        // consider only the `valid` chunks while constructing rows for the "chunk data" section.
        self.chunk_data
            .iter()
            .take(self.num_valid_chunks as usize)
            .enumerate()
            .flat_map(|(i, bytes)| {
                let chunk_idx = (i + 1) as u64;
                let chunk_size = bytes.len();
                let chunk_digest = keccak256(bytes);
                let digest_rlc = chunk_digest
                    .iter()
                    .fold(Value::known(Fr::zero()), |acc, &byte| {
                        acc * challenge.evm_word() + Value::known(Fr::from(byte as u64))
                    });
                bytes.iter().enumerate().scan(
                    (0u64, Value::known(Fr::zero())),
                    move |acc, (j, &byte)| {
                        acc.0 += 1;
                        acc.1 =
                            acc.1 * challenge.keccak_input() + Value::known(Fr::from(byte as u64));
                        Some(BatchDataRow {
                            byte,
                            accumulator: acc.0,
                            chunk_idx,
                            is_boundary: j == chunk_size - 1,
                            is_padding: false,
                            preimage_rlc: acc.1,
                            digest_rlc: if j == chunk_size - 1 {
                                digest_rlc
                            } else {
                                Value::known(Fr::zero())
                            },
                        })
                    },
                )
            })
            .chain(repeat(BatchDataRow::padding_row()))
            .take(Self::n_rows_data())
            .collect()
    }

    /// Get the witness rows for both "digest rlc" and "digest bytes" sections of Blob data config.
    fn to_digest_rows(
        &self,
        versioned_hash: H256,
        challenge: Challenges<Value<Fr>>,
    ) -> Vec<BatchDataRow<Fr>> {
        let zero = Value::known(Fr::zero());

        // metadata
        let metadata_bytes = self.to_metadata_bytes();
        let metadata_digest = keccak256(metadata_bytes);
        let metadata_digest_rlc = metadata_digest.iter().fold(zero, |acc, &byte| {
            acc * challenge.evm_word() + Value::known(Fr::from(byte as u64))
        });

        // chunk data
        // Note: here we don't restrict to considering only `valid` chunks, as the
        // `chunk_data_digest` gets repeated for the padded chunks, copying the last valid chunk's
        // `chunk_data_digest`.
        let (chunk_digests, chunk_digest_rlcs): (Vec<[u8; 32]>, Vec<Value<Fr>>) = self
            .chunk_data
            .iter()
            .map(|chunk| {
                let digest = keccak256(chunk);
                let digest_rlc = digest.iter().fold(zero, |acc, &byte| {
                    acc * challenge.evm_word() + Value::known(Fr::from(byte as u64))
                });
                (digest, digest_rlc)
            })
            .unzip();

        // challenge digest
        let challenge_digest_preimage = self.get_challenge_digest_preimage(versioned_hash);
        let challenge_digest_preimage_rlc =
            challenge_digest_preimage.iter().fold(zero, |acc, &byte| {
                acc * challenge.keccak_input() + Value::known(Fr::from(byte as u64))
            });
        let challenge_digest = keccak256(&challenge_digest_preimage);
        let challenge_digest_rlc = challenge_digest.iter().fold(zero, |acc, &byte| {
            acc * challenge.evm_word() + Value::known(Fr::from(byte as u64))
        });

        // blob versioned hash
        let versioned_hash_rlc = versioned_hash.as_bytes().iter().fold(zero, |acc, &byte| {
            acc * challenge.evm_word() + Value::known(Fr::from(byte as u64))
        });

        // - metadata digest rlc
        // - chunks[i].chunk_data_digest rlc for each chunk
        // - versioned hash rlc
        // - challenge digest rlc
        // - metadata digest bytes
        // - chunks[i].chunk_data_digest bytes for each chunk
        // - versioned hash bytes
        // - challenge digest bytes
        once(BatchDataRow {
            preimage_rlc: Value::known(Fr::zero()),
            digest_rlc: metadata_digest_rlc,
            // this is_padding assignment does not matter as we have already crossed the "chunk
            // data" section. This assignment to 1 is simply to allow the custom gate to check:
            // - padding transitions from 0 -> 1 only once.
            is_padding: true,
            ..Default::default()
        })
        .chain(
            chunk_digest_rlcs
                .iter()
                .zip_eq(self.chunk_sizes.iter())
                .enumerate()
                .map(|(i, (&digest_rlc, &chunk_size))| BatchDataRow {
                    preimage_rlc: Value::known(Fr::zero()),
                    digest_rlc,
                    chunk_idx: (i + 1) as u64,
                    accumulator: chunk_size as u64,
                    ..Default::default()
                }),
        )
        // versioned hash RLC
        .chain(once(BatchDataRow {
            preimage_rlc: Value::known(Fr::zero()),
            digest_rlc: versioned_hash_rlc,
            ..Default::default()
        }))
        .chain(once(BatchDataRow {
            preimage_rlc: challenge_digest_preimage_rlc,
            digest_rlc: challenge_digest_rlc,
            accumulator: 32 * (N_SNARKS + 1 + 1) as u64,
            is_boundary: true,
            ..Default::default()
        }))
        .chain(metadata_digest.iter().map(|&byte| BatchDataRow {
            preimage_rlc: Value::known(Fr::zero()),
            digest_rlc: Value::known(Fr::zero()),
            byte,
            ..Default::default()
        }))
        .chain(chunk_digests.iter().flat_map(|digest| {
            digest.iter().map(|&byte| BatchDataRow {
                preimage_rlc: Value::known(Fr::zero()),
                digest_rlc: Value::known(Fr::zero()),
                byte,
                ..Default::default()
            })
        }))
        // bytes of versioned hash
        .chain(versioned_hash.as_bytes().iter().map(|&byte| BatchDataRow {
            preimage_rlc: Value::known(Fr::zero()),
            digest_rlc: Value::known(Fr::zero()),
            byte,
            ..Default::default()
        }))
        .chain(challenge_digest.iter().map(|&byte| BatchDataRow {
            preimage_rlc: Value::known(Fr::zero()),
            digest_rlc: Value::known(Fr::zero()),
            byte,
            ..Default::default()
        }))
        .collect()
    }
}

/// Witness row to the Blob Data Config.
#[derive(Clone, Copy, Default, Debug)]
struct BatchDataRow<Fr> {
    /// Byte value at this row.
    pub byte: u8,
    /// Multi-purpose accumulator value.
    pub accumulator: u64,
    /// The chunk index we are currently traversing.
    pub chunk_idx: u64,
    /// Whether this marks the end of a chunk.
    pub is_boundary: bool,
    /// Whether the row represents right-padded 0s to the blob data.
    pub is_padding: bool,
    /// A running accumulator of RLC of preimages.
    pub preimage_rlc: Value<Fr>,
    /// RLC of the digest.
    pub digest_rlc: Value<Fr>,
}

impl BatchDataRow<Fr> {
    fn padding_row() -> Self {
        Self {
            is_padding: true,
            preimage_rlc: Value::known(Fr::zero()),
            digest_rlc: Value::known(Fr::zero()),
            ..Default::default()
        }
    }
}
