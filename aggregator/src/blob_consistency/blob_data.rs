use crate::{
    aggregation::{
        batch_data::{N_BLOB_BYTES, N_DATA_BYTES_PER_COEFFICIENT},
        POWS_OF_256,
    },
    blob_consistency::BLOB_WIDTH,
    RlcConfig,
};
use gadgets::util::Expr;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Fixed, SecondPhase, Selector},
    poly::Rotation,
};
use itertools::Itertools;
use snark_verifier_sdk::{BITS, LIMBS};
use zkevm_circuits::{table::U8Table, util::Challenges};

/// Blob is represented by 4096 BLS12-381 scalar field elements, where each element is represented
/// by 32 bytes. The scalar field element is required to be in the canonical form, i.e. its value
/// MUST BE less than the BLS_MODULUS. In order to ensure this, we hard-code the most-significant
/// byte in each 32-bytes chunk to zero, i.e. effectively we use only 31 bytes.
///
/// Since the check for the most-significant byte being zero is already done in the
/// BarycentricConfig, in the BlobDataConfig we only represent the 31 meaningful bytes. Hence the
/// BlobDataConfig has 4096 * 31 rows. Each row is a byte value and the purpose of the
/// BlobDataConfig is to compute a random-linear combination of these bytes. These bytes are in
/// fact the zstd encoded form of the raw batch data represented in BatchDataConfig.
#[derive(Clone, Debug)]
pub struct BlobDataConfig<const N_SNARKS: usize> {
    /// Selector to mark the first row in the layout, enabled at offset=0.
    q_first: Column<Fixed>,
    /// Whether the row is enabled or not. We need exactly N_BLOB_BYTES rows, enabled from offset=1
    /// to offset=N_BLOB_BYTES.
    q_enabled: Selector,
    /// The byte value at this row.
    byte: Column<Advice>,
    /// Whether or not this is a padded row. This can be the case if not all bytes in the blob
    /// (4096 * 31) could be filled. Padded bytes must be 0 and bytes_rlc must continue while in
    /// the padded region.
    is_padding: Column<Advice>,
    /// running RLC of bytes seen so far. It remains unchanged once padded territory starts.
    bytes_rlc: Column<Advice>,
    /// running accumulator of the number of bytes in the blob.
    bytes_len: Column<Advice>,
}

pub struct AssignedBlobDataExport {
    pub enable_encoding_bool: bool,
    pub enable_encoding: AssignedCell<Fr, Fr>,
    pub bytes_rlc: AssignedCell<Fr, Fr>,
    pub bytes_len: AssignedCell<Fr, Fr>,
    pub cooked_len: AssignedCell<Fr, Fr>,
    pub blob_crts_limbs: [[AssignedCell<Fr, Fr>; LIMBS]; BLOB_WIDTH],
}

impl<const N_SNARKS: usize> BlobDataConfig<N_SNARKS> {
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        challenges: &Challenges<Expression<Fr>>,
        u8_table: U8Table,
    ) -> Self {
        let config = Self {
            q_first: meta.fixed_column(),
            q_enabled: meta.selector(),
            byte: meta.advice_column(),
            is_padding: meta.advice_column(),
            bytes_rlc: meta.advice_column_in(SecondPhase),
            bytes_len: meta.advice_column(),
        };

        meta.enable_equality(config.byte);
        meta.enable_equality(config.bytes_rlc);
        meta.enable_equality(config.bytes_len);

        meta.lookup("BlobDataConfig (0 < byte < 256)", |meta| {
            let byte_value = meta.query_advice(config.byte, Rotation::cur());
            vec![(byte_value, u8_table.into())]
        });

        meta.create_gate("BlobDataConfig: first row", |meta| {
            let is_first = meta.query_fixed(config.q_first, Rotation::cur());

            let byte = meta.query_advice(config.byte, Rotation::cur());
            let bytes_rlc = meta.query_advice(config.bytes_rlc, Rotation::cur());
            let bytes_len = meta.query_advice(config.bytes_len, Rotation::cur());
            let is_padding_next = meta.query_advice(config.is_padding, Rotation::next());

            let bytes_rlc_next = meta.query_advice(config.bytes_rlc, Rotation::next());
            let bytes_len_next = meta.query_advice(config.bytes_len, Rotation::next());

            vec![
                is_first.expr() * byte,
                is_first.expr() * bytes_rlc,
                is_first.expr() * bytes_rlc_next,
                is_first.expr() * bytes_len,
                is_first.expr() * bytes_len_next,
                is_first.expr() * is_padding_next,
            ]
        });

        meta.create_gate("BlobDataConfig: main gate", |meta| {
            let is_enabled = meta.query_selector(config.q_enabled);
            let is_skip_rlc = meta.query_fixed(config.q_first, Rotation::prev());
            let trigger_rlc = 1.expr() - is_skip_rlc;

            let is_padding_curr = meta.query_advice(config.is_padding, Rotation::cur());
            let is_padding_prev = meta.query_advice(config.is_padding, Rotation::prev());
            let delta = is_padding_curr.expr() - is_padding_prev.expr();

            let byte = meta.query_advice(config.byte, Rotation::cur());

            let bytes_rlc_curr = meta.query_advice(config.bytes_rlc, Rotation::cur());
            let bytes_rlc_prev = meta.query_advice(config.bytes_rlc, Rotation::prev());

            let bytes_len_curr = meta.query_advice(config.bytes_len, Rotation::cur());
            let bytes_len_prev = meta.query_advice(config.bytes_len, Rotation::prev());

            vec![
                // if is_padding: byte == 0
                is_enabled.expr() * is_padding_curr.expr() * byte.expr(),
                // is_padding is boolean
                is_enabled.expr() * is_padding_curr.expr() * (1.expr() - is_padding_curr.expr()),
                // is_padding transitions from 0 -> 1 only once
                is_enabled.expr() * delta.expr() * (1.expr() - delta.expr()),
                // bytes_rlc updates in the non-padded territory
                is_enabled.expr()
                    * (1.expr() - is_padding_curr.expr())
                    * trigger_rlc.expr()
                    * (bytes_rlc_prev.expr() * challenges.keccak_input() + byte.expr()
                        - bytes_rlc_curr.expr()),
                // bytes_rlc remains unchanged in padded territory
                is_enabled.expr()
                    * is_padding_curr.expr()
                    * (bytes_rlc_curr.expr() - bytes_rlc_prev.expr()),
                // bytes_len increments in the non-padded territory
                is_enabled.expr()
                    * (1.expr() - is_padding_curr.expr())
                    * trigger_rlc.expr()
                    * (bytes_len_prev.expr() + 1.expr() - bytes_len_curr.expr()),
                // bytes_len remains unchanged in padded territory
                is_enabled.expr()
                    * is_padding_curr.expr()
                    * (bytes_len_curr.expr() - bytes_len_prev.expr()),
            ]
        });

        assert!(meta.degree() <= 4);

        config
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<Fr>,
        challenge_value: Challenges<Value<Fr>>,
        rlc_config: &RlcConfig,
        blob_bytes: &[u8],
    ) -> Result<AssignedBlobDataExport, Error> {
        let (assigned_bytes, bytes_rlc, bytes_len, enable_encoding_bool) = layouter.assign_region(
            || "BlobData bytes",
            |mut region| self.assign_rows(&mut region, blob_bytes, &challenge_value),
        )?;
        let enable_encoding = assigned_bytes[0].clone();

        let (cooked_len, blob_crts_limbs) = layouter.assign_region(
            || "BlobData internal checks",
            |mut region| {
                self.assign_internal_checks(&mut region, rlc_config, &assigned_bytes, &bytes_len)
            },
        )?;

        Ok(AssignedBlobDataExport {
            enable_encoding_bool,
            enable_encoding,
            bytes_rlc,
            bytes_len,
            cooked_len,
            blob_crts_limbs,
        })
    }

    #[allow(clippy::type_complexity)]
    pub fn assign_rows(
        &self,
        region: &mut Region<Fr>,
        blob_bytes: &[u8],
        challenges: &Challenges<Value<Fr>>,
    ) -> Result<
        (
            Vec<AssignedCell<Fr, Fr>>,
            AssignedCell<Fr, Fr>,
            AssignedCell<Fr, Fr>,
            bool,
        ),
        Error,
    > {
        let enable_encoding = blob_bytes[0].eq(&1);

        assert!(blob_bytes.len() <= N_BLOB_BYTES, "too many blob bytes");

        // Assign fixed column and selector.
        region.assign_fixed(|| "q_first", self.q_first, 0, || Value::known(Fr::one()))?;
        for i in 1..=N_BLOB_BYTES {
            self.q_enabled.enable(region, i)?;
            region.assign_fixed(|| "q_first", self.q_first, i, || Value::known(Fr::zero()))?;
        }

        for col in [self.byte, self.bytes_rlc, self.bytes_len, self.is_padding] {
            region.assign_advice(
                || "advice at q_first=1",
                col,
                0,
                || Value::known(Fr::zero()),
            )?;
        }

        let mut assigned_bytes = Vec::with_capacity(N_BLOB_BYTES);
        let mut bytes_rlc = Value::known(Fr::zero());
        let mut last_bytes_rlc = None;
        let mut last_bytes_len = None;
        for (i, &byte) in blob_bytes.iter().enumerate() {
            let byte_value = Value::known(Fr::from(byte as u64));
            if i > 0 {
                bytes_rlc = bytes_rlc * challenges.keccak_input() + byte_value;
            }

            let offset = i + 1;
            assigned_bytes.push(region.assign_advice(
                || "byte",
                self.byte,
                offset,
                || byte_value,
            )?);
            region.assign_advice(
                || "is_padding",
                self.is_padding,
                offset,
                || Value::known(Fr::zero()),
            )?;
            last_bytes_rlc =
                Some(region.assign_advice(|| "bytes_rlc", self.bytes_rlc, offset, || bytes_rlc)?);
            last_bytes_len = Some(region.assign_advice(
                || "bytes_len",
                self.bytes_len,
                offset,
                || Value::known(Fr::from(i as u64)),
            )?);
        }

        let mut last_bytes_rlc = last_bytes_rlc.expect("at least 1 byte guaranteed");
        let mut last_bytes_len = last_bytes_len.expect("at least 1 byte guaranteed");
        for i in blob_bytes.len()..N_BLOB_BYTES {
            let offset = i + 1;
            assigned_bytes.push(region.assign_advice(
                || "byte",
                self.byte,
                offset,
                || Value::known(Fr::zero()),
            )?);
            region.assign_advice(
                || "is_padding",
                self.is_padding,
                offset,
                || Value::known(Fr::one()),
            )?;
            last_bytes_rlc = region.assign_advice(
                || "bytes_rlc",
                self.bytes_rlc,
                offset,
                || last_bytes_rlc.value().cloned(),
            )?;
            last_bytes_len = region.assign_advice(
                || "bytes_len",
                self.bytes_len,
                offset,
                || last_bytes_len.value().cloned(),
            )?;
        }

        Ok((
            assigned_bytes,
            last_bytes_rlc,
            last_bytes_len,
            enable_encoding,
        ))
    }

    #[allow(clippy::type_complexity)]
    pub fn assign_internal_checks(
        &self,
        region: &mut Region<Fr>,
        rlc_config: &RlcConfig,
        assigned_bytes: &[AssignedCell<Fr, Fr>],
        bytes_len: &AssignedCell<Fr, Fr>,
    ) -> Result<
        (
            AssignedCell<Fr, Fr>,
            [[AssignedCell<Fr, Fr>; LIMBS]; BLOB_WIDTH],
        ),
        Error,
    > {
        rlc_config.init(region)?;
        let mut rlc_config_offset = 0;

        // load some constants that we will use later.
        let one = {
            let one = rlc_config.load_private(region, &Fr::one(), &mut rlc_config_offset)?;
            let one_cell = rlc_config.one_cell(one.cell().region_index);
            region.constrain_equal(one.cell(), one_cell)?;
            one
        };
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

        // The first byte in the blob is a boolean indicating whether or not blob is an encoded
        // form of the batch.
        rlc_config.enforce_binary(region, &assigned_bytes[0], &mut rlc_config_offset)?;

        // Compute 88 bit limbs so we can later check to equality to the inputs in the barycentric
        // evaluation circuit.
        let blob_crts_limbs = blob_crts_limbs(
            region,
            rlc_config,
            assigned_bytes,
            &pows_of_256,
            &mut rlc_config_offset,
        );

        // The zstd decoder (DecoderConfig) exports an encoded length that is 1 more than the
        // actual number of bytes in encoded data. Accordingly we "cook" the actual len(bytes) here
        // by adding +1 to it before exporting.
        let cooked_bytes_len = rlc_config.add(region, bytes_len, &one, &mut rlc_config_offset)?;

        Ok((cooked_bytes_len, blob_crts_limbs))
    }
}

fn blob_crts_limbs(
    region: &mut Region<Fr>,
    rlc_config: &RlcConfig,
    bytes: &[AssignedCell<Fr, Fr>],
    powers_of_256: &[AssignedCell<Fr, Fr>],
    offset: &mut usize,
) -> [[AssignedCell<Fr, Fr>; LIMBS]; BLOB_WIDTH] {
    bytes
        .chunks_exact(N_DATA_BYTES_PER_COEFFICIENT)
        .map(|coefficient_bytes| {
            coefficient_bytes
                .iter()
                .rev() // reverse bytes to match endianness of crt limbs
                .chunks(BITS / 8)
                .into_iter()
                .map(|chunk_bytes| {
                    let chunk_bytes = chunk_bytes.into_iter().cloned().collect_vec();
                    rlc_config
                        .inner_product(
                            region,
                            &chunk_bytes,
                            &powers_of_256[..chunk_bytes.len()],
                            offset,
                        )
                        .unwrap()
                })
                .collect_vec()
                .try_into()
                .unwrap()
        })
        .collect_vec()
        .try_into()
        .unwrap()
}
