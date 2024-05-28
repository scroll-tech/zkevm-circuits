use std::io::Write;

use gadgets::util::Expr;
use halo2_ecc::bigint::CRTInteger;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, SecondPhase, Selector},
    poly::Rotation,
};
use itertools::Itertools;
use zkevm_circuits::{table::U8Table, util::Challenges};

use crate::{
    aggregation::{decoder::witgen::init_zstd_encoder, rlc::POWS_OF_256},
    blob::{BatchData, BLOB_WIDTH, N_BLOB_BYTES, N_DATA_BYTES_PER_COEFFICIENT},
    RlcConfig,
};

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
    q_first: Selector,
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
    pub bytes_rlc: AssignedCell<Fr, Fr>,
    pub bytes_len: AssignedCell<Fr, Fr>,
}

impl<const N_SNARKS: usize> BlobDataConfig<N_SNARKS> {
    pub fn configure(
        meta: &mut ConstraintSystem<Fr>,
        challenges: &Challenges<Expression<Fr>>,
        u8_table: U8Table,
    ) -> Self {
        let config = Self {
            q_enabled: meta.selector(),
            q_first: meta.complex_selector(),
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
            let is_first = meta.query_selector(config.q_first);

            let byte = meta.query_advice(config.byte, Rotation::cur());
            let bytes_rlc = meta.query_advice(config.bytes_rlc, Rotation::cur());
            let bytes_len = meta.query_advice(config.bytes_len, Rotation::cur());
            let is_padding_next = meta.query_advice(config.is_padding, Rotation::next());

            vec![
                is_first.expr() * byte,
                is_first.expr() * bytes_rlc,
                is_first.expr() * bytes_len,
                is_first.expr() * is_padding_next,
            ]
        });

        meta.create_gate("BlobDataConfig: main gate", |meta| {
            let is_enabled = meta.query_selector(config.q_enabled);

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
                    * (bytes_rlc_prev.expr() * challenges.keccak_input() + byte.expr()
                        - bytes_rlc_curr.expr()),
                // bytes_rlc remains unchanged in padded territory
                is_enabled.expr()
                    * is_padding_curr.expr()
                    * (bytes_rlc_curr.expr() - bytes_rlc_prev.expr()),
                // bytes_len increments in the non-padded territory
                is_enabled.expr()
                    * (1.expr() - is_padding_curr.expr())
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
        batch_data: &BatchData<N_SNARKS>,
        barycentric_assignments: &[CRTInteger<Fr>],
    ) -> Result<AssignedBlobDataExport, Error> {
        let (assigned_bytes, bytes_rlc, bytes_len) = layouter.assign_region(
            || "BlobData bytes",
            |mut region| self.assign_rows(&mut region, batch_data, &challenge_value),
        )?;

        let cooked_bytes_len = layouter.assign_region(
            || "BlobData internal checks",
            |mut region| {
                self.assign_internal_checks(
                    &mut region,
                    rlc_config,
                    barycentric_assignments,
                    &assigned_bytes,
                    &bytes_len,
                )
            },
        )?;

        Ok(AssignedBlobDataExport {
            bytes_rlc,
            bytes_len: cooked_bytes_len,
        })
    }

    #[allow(clippy::type_complexity)]
    pub fn assign_rows(
        &self,
        region: &mut Region<Fr>,
        batch_data: &BatchData<N_SNARKS>,
        challenges: &Challenges<Value<Fr>>,
    ) -> Result<
        (
            Vec<AssignedCell<Fr, Fr>>,
            AssignedCell<Fr, Fr>,
            AssignedCell<Fr, Fr>,
        ),
        Error,
    > {
        let batch_bytes = batch_data.get_batch_data_bytes();
        let blob_bytes = {
            let mut encoder = init_zstd_encoder(None);
            encoder
                .set_pledged_src_size(Some(batch_bytes.len() as u64))
                .map_err(|_| Error::Synthesis)?;
            encoder
                .write_all(&batch_bytes)
                .map_err(|_| Error::Synthesis)?;
            encoder.finish().map_err(|_| Error::Synthesis)?
        };
        assert!(blob_bytes.len() <= N_BLOB_BYTES, "too many blob bytes");

        self.q_first.enable(region, 0)?;
        for i in 1..=N_BLOB_BYTES {
            self.q_enabled.enable(region, i)?;
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
            bytes_rlc = bytes_rlc * challenges.keccak_input() + byte_value;

            assigned_bytes.push(region.assign_advice(
                || "byte",
                self.byte,
                i + 1,
                || byte_value,
            )?);
            region.assign_advice(
                || "is_padding",
                self.is_padding,
                i + 1,
                || Value::known(Fr::zero()),
            )?;
            last_bytes_rlc =
                Some(region.assign_advice(|| "bytes_rlc", self.bytes_rlc, i + 1, || bytes_rlc)?);
            last_bytes_len = Some(region.assign_advice(
                || "bytes_len",
                self.bytes_len,
                i + 1,
                || Value::known(Fr::from(i as u64 + 1)),
            )?);
        }

        let mut last_bytes_rlc = last_bytes_rlc.expect("at least 1 byte guaranteed");
        let mut last_bytes_len = last_bytes_len.expect("at least 1 byte guaranteed");
        for i in blob_bytes.len()..N_BLOB_BYTES {
            assigned_bytes.push(region.assign_advice(
                || "byte",
                self.byte,
                i + 1,
                || Value::known(Fr::zero()),
            )?);
            region.assign_advice(
                || "is_padding",
                self.is_padding,
                i + 1,
                || Value::known(Fr::one()),
            )?;
            last_bytes_rlc = region.assign_advice(
                || "bytes_rlc",
                self.bytes_rlc,
                i + 1,
                || last_bytes_rlc.value().cloned(),
            )?;
            last_bytes_len = region.assign_advice(
                || "bytes_len",
                self.bytes_len,
                i + 1,
                || last_bytes_len.value().cloned(),
            )?;
        }

        Ok((assigned_bytes, last_bytes_rlc, last_bytes_len))
    }

    pub fn assign_internal_checks(
        &self,
        region: &mut Region<Fr>,
        rlc_config: &RlcConfig,
        barycentric_assignments: &[CRTInteger<Fr>],
        assigned_bytes: &[AssignedCell<Fr, Fr>],
        bytes_len: &AssignedCell<Fr, Fr>,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
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

        ////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////// LINKING ///////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////

        assert_eq!(barycentric_assignments.len(), BLOB_WIDTH + 1);
        let blob_crts = barycentric_assignments
            .iter()
            .take(BLOB_WIDTH)
            .collect::<Vec<_>>();
        let mut blob_fields: Vec<Vec<AssignedCell<Fr, Fr>>> = Vec::with_capacity(BLOB_WIDTH);
        for chunk in assigned_bytes.chunks_exact(N_DATA_BYTES_PER_COEFFICIENT) {
            // blob bytes are supposed to be deserialised in big-endianness. However, we
            // have the export from BarycentricConfig in little-endian bytes.
            blob_fields.push(chunk.iter().rev().cloned().collect());
        }

        for (blob_crt, blob_field) in blob_crts.iter().zip_eq(blob_fields.iter()) {
            let limb1 = rlc_config.inner_product(
                region,
                &blob_field[0..11],
                &pows_of_256,
                &mut rlc_config_offset,
            )?;
            let limb2 = rlc_config.inner_product(
                region,
                &blob_field[11..22],
                &pows_of_256,
                &mut rlc_config_offset,
            )?;
            let limb3 = rlc_config.inner_product(
                region,
                &blob_field[22..31],
                &pows_of_256[0..9],
                &mut rlc_config_offset,
            )?;
            region.constrain_equal(limb1.cell(), blob_crt.truncation.limbs[0].cell())?;
            region.constrain_equal(limb2.cell(), blob_crt.truncation.limbs[1].cell())?;
            region.constrain_equal(limb3.cell(), blob_crt.truncation.limbs[2].cell())?;
        }

        // The zstd decoder (DecoderConfig) exports an encoded length that is 1 more than the
        // actual number of bytes in encoded data. Accordingly we "cook" the actual len(bytes) here
        // by adding +1 to it before exporting.
        let cooked_bytes_len = rlc_config.add(region, bytes_len, &one, &mut rlc_config_offset)?;

        Ok(cooked_bytes_len)
    }
}
