use std::io::Write;

use halo2_ecc::bigint::CRTInteger;
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, Value},
    halo2curves::bn256::Fr,
    plonk::{Advice, Column, ConstraintSystem, Error},
    poly::Rotation,
};
use itertools::Itertools;
use zkevm_circuits::{table::U8Table, util::Challenges};

use crate::{
    aggregation::rlc::POWS_OF_256,
    blob::{init_zstd_encoder, BatchData, BLOB_WIDTH, N_BLOB_BYTES, N_DATA_BYTES_PER_COEFFICIENT},
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
pub struct BlobDataConfig {
    /// The byte value at this row.
    byte: Column<Advice>,
}

pub struct AssignedBlobDataExport {
    pub bytes_rlc: AssignedCell<Fr, Fr>,
}

impl BlobDataConfig {
    pub fn configure(meta: &mut ConstraintSystem<Fr>, u8_table: U8Table) -> Self {
        let config = Self {
            byte: meta.advice_column(),
        };

        meta.enable_equality(config.byte);

        meta.lookup("BlobDataConfig (0 < byte < 256)", |meta| {
            let byte_value = meta.query_advice(config.byte, Rotation::cur());
            vec![(byte_value, u8_table.into())]
        });

        assert!(meta.degree() <= 4);

        config
    }

    pub fn assign(
        &self,
        layouter: &mut impl Layouter<Fr>,
        challenge_value: Challenges<Value<Fr>>,
        rlc_config: &RlcConfig,
        batch_data: &BatchData,
        barycentric_assignments: &[CRTInteger<Fr>],
    ) -> Result<AssignedBlobDataExport, Error> {
        let assigned_bytes = layouter.assign_region(
            || "BlobData bytes",
            |mut region| self.assign_rows(&mut region, batch_data),
        )?;

        layouter.assign_region(
            || "BlobData internal checks",
            |mut region| {
                self.assign_internal_checks(
                    &mut region,
                    challenge_value,
                    rlc_config,
                    barycentric_assignments,
                    &assigned_bytes,
                )
            },
        )
    }

    pub fn assign_rows(
        &self,
        region: &mut Region<Fr>,
        batch_data: &BatchData,
    ) -> Result<Vec<AssignedCell<Fr, Fr>>, Error> {
        let batch_bytes = batch_data.get_batch_data_bytes();
        let blob_bytes = {
            let mut encoder = init_zstd_encoder();
            encoder
                .set_pledged_src_size(Some(batch_bytes.len() as u64))
                .map_err(|_| Error::Synthesis)?;
            encoder
                .write_all(&batch_bytes)
                .map_err(|_| Error::Synthesis)?;
            encoder.finish().map_err(|_| Error::Synthesis)?
        };
        assert!(blob_bytes.len() <= N_BLOB_BYTES, "too many blob bytes");

        let mut assigned_bytes = Vec::with_capacity(N_BLOB_BYTES);
        for (i, &byte) in blob_bytes
            .iter()
            .chain(std::iter::repeat(&0))
            .take(N_BLOB_BYTES)
            .enumerate()
        {
            assigned_bytes.push(region.assign_advice(
                || "byte",
                self.byte,
                i,
                || Value::known(Fr::from(byte as u64)),
            )?);
        }

        Ok(assigned_bytes)
    }

    pub fn assign_internal_checks(
        &self,
        region: &mut Region<Fr>,
        challenge_value: Challenges<Value<Fr>>,
        rlc_config: &RlcConfig,
        barycentric_assignments: &[CRTInteger<Fr>],
        assigned_bytes: &[AssignedCell<Fr, Fr>],
    ) -> Result<AssignedBlobDataExport, Error> {
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

        // read randomness challenges for RLC computations.
        let r_keccak =
            rlc_config.read_challenge1(region, challenge_value, &mut rlc_config_offset)?;

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

        ////////////////////////////////////////////////////////////////////////////////
        //////////////////////////////////// EXPORT ////////////////////////////////////
        ////////////////////////////////////////////////////////////////////////////////

        let bytes_rlc =
            rlc_config.rlc(region, assigned_bytes, &r_keccak, &mut rlc_config_offset)?;
        Ok(AssignedBlobDataExport { bytes_rlc })
    }
}
