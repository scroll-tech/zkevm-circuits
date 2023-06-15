//! Circuit to verify multiple ECDSA secp256k1 signatures.
//
// This module uses halo2-ecc's ecdsa chip
//  - to prove the correctness of secp signatures
//  - to compute the RLC in circuit
//  - to perform keccak lookup table
//
// Naming notes:
// - *_be: Big-Endian bytes
// - *_le: Little-Endian bytes

#[cfg(any(feature = "test", test, feature = "test-circuits"))]
mod dev;
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
mod test;

use crate::{
    evm_circuit::util::{not, rlc},
    table::{KeccakTable, SigTable},
    util::{Challenges, Expr, SubCircuit, SubCircuitConfig},
};
use eth_types::{
    self,
    sign_types::{pk_bytes_le, pk_bytes_swap_endianness, SignData},
    Field,
};
use halo2_base::{
    gates::{range::RangeConfig, GateInstructions},
    utils::modulus,
    AssignedValue, Context, QuantumCell, SKIP_FIRST_PASS,
};
use halo2_ecc::{
    bigint::CRTInteger,
    ecc::{ecdsa::ecdsa_verify_no_pubkey_check, EccChip},
    fields::{
        fp::{FpConfig, FpStrategy},
        FieldChip,
    },
};

mod utils;
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
pub(crate) use utils::*;

use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::secp256k1::{Fp, Fq, Secp256k1Affine},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

use itertools::Itertools;
use keccak256::plain::Keccak;
use log::error;
use std::{iter, marker::PhantomData};

/// Circuit configuration arguments
pub struct SigCircuitConfigArgs<F: Field> {
    /// KeccakTable
    pub keccak_table: KeccakTable,
    /// SigTable
    pub sig_table: SigTable,
    /// Challenges
    pub challenges: Challenges<Expression<F>>,
}

/// SignVerify Configuration
#[derive(Debug, Clone)]
pub struct SigCircuitConfig<F: Field> {
    /// ECDSA
    ecdsa_config: FpChip<F>,
    /// An advice column to store RLC witnesses
    rlc_column: Column<Advice>,
    /// selector for keccak lookup table
    q_keccak: Selector,
    /// Used to lookup pk->pk_hash(addr)
    keccak_table: KeccakTable,
    /// The exposed table to be used by tx circuit and ecrecover
    sig_table: SigTable,
}

impl<F: Field> SubCircuitConfig<F> for SigCircuitConfig<F> {
    type ConfigArgs = SigCircuitConfigArgs<F>;

    /// Return a new SigConfig
    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            keccak_table,
            sig_table,
            challenges: _,
        }: Self::ConfigArgs,
    ) -> Self {
        #[cfg(feature = "onephase")]
        let num_advice = [calc_required_advices(MAX_NUM_SIG)];
        #[cfg(not(feature = "onephase"))]
        // need an additional phase 2 column/basic gate to hold the witnesses during RLC
        // computations
        let num_advice = [calc_required_advices(MAX_NUM_SIG), 1];

        #[cfg(feature = "onephase")]
        log::debug!("configuring ECDSA chip with single phase");
        #[cfg(not(feature = "onephase"))]
        log::debug!("configuring ECDSA chip with multiple phases");

        // halo2-ecc's ECDSA config
        //
        // - num_advice: 36
        // - num_lookup_advice: 17
        // - num_fixed: 1
        // - lookup_bits: 13
        // - limb_bits: 88
        // - num_limbs: 3
        //
        // TODO: make those parameters tunable from a config file
        let ecdsa_config = FpConfig::configure(
            meta,
            FpStrategy::Simple,
            &num_advice,
            &[17],
            1,
            13,
            88,
            3,
            modulus::<Fp>(),
            0,
            LOG_TOTAL_NUM_ROWS, // maximum k of the chip
        );

        // we are not really using this instance column
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        // we need one phase 2 column to store RLC results
        #[cfg(feature = "onephase")]
        let rlc_column = meta.advice_column_in(halo2_proofs::plonk::FirstPhase);
        #[cfg(not(feature = "onephase"))]
        let rlc_column = meta.advice_column_in(halo2_proofs::plonk::SecondPhase);

        meta.enable_equality(rlc_column);

        meta.enable_equality(sig_table.recovered_addr);
        meta.enable_equality(sig_table.sig_r_rlc);
        meta.enable_equality(sig_table.sig_s_rlc);
        //meta.enable_equality(ec_recover_table.v);
        meta.enable_equality(sig_table.is_valid);
        meta.enable_equality(sig_table.msg_hash_rlc);

        // Ref. spec SignVerifyChip 1. Verify that keccak(pub_key_bytes) = pub_key_hash
        // by keccak table lookup, where pub_key_bytes is built from the pub_key
        // in the ecdsa_chip.
        let q_keccak = meta.complex_selector();

        meta.lookup_any("keccak lookup table", |meta| {
            // When address is 0, we disable the signature verification by using a dummy pk,
            // msg_hash and signature which is not constrained to match msg_hash_rlc nor
            // the address.
            // Layout:
            // | q_keccak |       rlc       |
            // | -------- | --------------- |
            // |     1    | is_address_zero |
            // |          |    pk_rlc       |
            // |          |    pk_hash_rlc  |
            let q_keccak = meta.query_selector(q_keccak);
            let is_address_zero = meta.query_advice(rlc_column, Rotation::cur());
            let is_enable = q_keccak * not::expr(is_address_zero);

            let input = [
                is_enable.clone(),
                is_enable.clone(),
                is_enable.clone() * meta.query_advice(rlc_column, Rotation(1)),
                is_enable.clone() * 64usize.expr(),
                is_enable * meta.query_advice(rlc_column, Rotation(2)),
            ];
            let table = [
                meta.query_fixed(keccak_table.q_enable, Rotation::cur()),
                meta.query_advice(keccak_table.is_final, Rotation::cur()),
                meta.query_advice(keccak_table.input_rlc, Rotation::cur()),
                meta.query_advice(keccak_table.input_len, Rotation::cur()),
                meta.query_advice(keccak_table.output_rlc, Rotation::cur()),
            ];

            input.into_iter().zip(table).collect()
        });

        Self {
            ecdsa_config,
            keccak_table,
            sig_table,
            q_keccak,
            rlc_column,
        }
    }
}

impl<F: Field> SigCircuitConfig<F> {
    pub(crate) fn load_range(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.ecdsa_config.range.load_lookup_table(layouter)
    }
}

/// Verify a message hash is signed by the public
/// key corresponding to an Ethereum Address.
#[derive(Clone, Debug, Default)]
pub struct SigCircuit<F: Field> {
    /// Max number of verifications
    pub max_verif: usize,
    /// Without padding
    pub signatures: Vec<SignData>,
    /// Marker
    pub _marker: PhantomData<F>,
}

impl<F: Field> SubCircuit<F> for SigCircuit<F> {
    type Config = SigCircuitConfig<F>;

    fn new_from_block(block: &crate::witness::Block<F>) -> Self {
        SigCircuit {
            // TODO: seperate max_verif with max_txs?
            max_verif: block.circuits_params.max_txs,
            // TODO: better way than unwrap?
            signatures: block.get_sign_data(true).unwrap(),
            _marker: Default::default(),
        }
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        config.ecdsa_config.range.load_lookup_table(layouter)?;
        self.assign(config, layouter, &self.signatures, challenges)?;
        Ok(())
    }

    // Since sig circuit / halo2-lib use veticle cell assignment,
    // so the returned pair is consisted of same values
    fn min_num_rows_block(block: &crate::witness::Block<F>) -> (usize, usize) {
        let row_num = Self::min_num_rows(block.circuits_params.max_txs);
        (row_num, row_num)
    }
}

impl<F: Field> SigCircuit<F> {
    /// Return a new SigCircuit
    pub fn new(max_verif: usize) -> Self {
        Self {
            max_verif,
            signatures: Vec::new(),
            _marker: PhantomData,
        }
    }

    /// Return the minimum number of rows required to prove an input of a
    /// particular size.
    /// TODO: minus 256?
    pub fn min_num_rows(num_verif: usize) -> usize {
        // the cells are allocated vertically, i.e., given a TOTAL_NUM_ROWS * NUM_ADVICE
        // matrix, the allocator will try to use all the cells in the first column, then
        // the second column, etc.
        let row_num = 1 << LOG_TOTAL_NUM_ROWS;
        let col_num = calc_required_advices(num_verif);
        if num_verif * CELLS_PER_SIG > col_num * row_num {
            log::error!(
                "ecdsa chip not enough rows. rows: {}, advice {}, num of sigs {}, cells per sig {}",
                row_num,
                col_num,
                num_verif,
                CELLS_PER_SIG
            )
        } else {
            log::debug!(
                "ecdsa chip: rows: {}, advice {}, num of sigs {}, cells per sig {}",
                row_num,
                col_num,
                num_verif,
                CELLS_PER_SIG
            )
        }

        row_num
    }
}

impl<F: Field> SigCircuit<F> {
    /// Verifies the ecdsa relationship. I.e., prove that the signature
    /// is (in)valid or not under the given public key and the message hash in
    /// the circuit. Does not enforce the signature is valid.
    ///
    /// Returns the cells for
    /// - public keys
    /// - message hashes
    /// - a boolean whether the signature is correct or not
    ///
    /// WARNING: this circuit does not enforce the returned value to be true
    /// make sure the caller checks this result!
    fn assign_ecdsa<'v>(
        &self,
        ctx: &mut Context<'v, F>,
        ecdsa_chip: &FpChip<F>,
        sign_data: &SignData,
    ) -> Result<AssignedECDSA<'v, F, FpChip<F>>, Error> {
        log::trace!("start ecdsa assignment");
        let SignData {
            signature,
            pk,
            msg: _,
            msg_hash,
        } = sign_data;
        let (sig_r, sig_s, v) = signature;

        // build ecc chip from Fp chip
        let ecc_chip = EccChip::<F, FpChip<F>>::construct(ecdsa_chip.clone());
        // build Fq chip from Fp chip
        let fq_chip = FqChip::construct(ecdsa_chip.range.clone(), 88, 3, modulus::<Fq>());

        log::trace!("r: {:?}", sig_r);
        log::trace!("s: {:?}", sig_s);
        log::trace!("msg: {:?}", msg_hash);

        let integer_r =
            fq_chip.load_private(ctx, FqChip::<F>::fe_to_witness(&Value::known(*sig_r)));
        log::trace!("r: {:?}", integer_r);

        let integer_s =
            fq_chip.load_private(ctx, FqChip::<F>::fe_to_witness(&Value::known(*sig_s)));
        let msg_hash =
            fq_chip.load_private(ctx, FqChip::<F>::fe_to_witness(&Value::known(*msg_hash)));
        let pk_assigned = ecc_chip.load_private(ctx, (Value::known(pk.x), Value::known(pk.y)));

        // returns the verification result of ecdsa signature
        //
        // WARNING: this circuit does not enforce the returned value to be true
        // make sure the caller checks this result!
        let ecdsa_is_valid = ecdsa_verify_no_pubkey_check::<F, Fp, Fq, Secp256k1Affine>(
            &ecc_chip.field_chip,
            ctx,
            &pk_assigned,
            &integer_r,
            &integer_s,
            &msg_hash,
            4,
            4,
        );
        log::trace!("ECDSA res {:?}", ecdsa_is_valid);

        Ok(AssignedECDSA {
            pk: pk_assigned,
            msg_hash,
            integer_r,
            integer_s,
            sig_is_valid: ecdsa_is_valid,
        })
    }

    fn enable_keccak_lookup(
        &self,
        config: &SigCircuitConfig<F>,
        ctx: &mut Context<F>,
        offset: &mut usize,
        is_address_zero: &AssignedValue<F>,
        pk_rlc: &AssignedValue<F>,
        pk_hash_rlc: &AssignedValue<F>,
    ) -> Result<(), Error> {
        log::trace!("keccak lookup");

        // Layout:
        // | q_keccak |        rlc      |
        // | -------- | --------------- |
        // |     1    | is_address_zero |
        // |          |    pk_rlc       |
        // |          |    pk_hash_rlc  |
        config.q_keccak.enable(&mut ctx.region, *offset)?;

        // is_address_zero
        let tmp_cell = ctx.region.assign_advice(
            || "is_address_zero",
            config.rlc_column,
            *offset,
            || is_address_zero.value,
        )?;
        ctx.region
            .constrain_equal(is_address_zero.cell, tmp_cell.cell())?;

        // pk_rlc
        let tmp_cell = ctx.region.assign_advice(
            || "pk_rlc",
            config.rlc_column,
            *offset + 1,
            || pk_rlc.value,
        )?;
        ctx.region.constrain_equal(pk_rlc.cell, tmp_cell.cell())?;

        // pk_hash_rlc
        let tmp_cell = ctx.region.assign_advice(
            || "pk_hash_rlc",
            config.rlc_column,
            *offset + 2,
            || pk_hash_rlc.value,
        )?;
        ctx.region
            .constrain_equal(pk_hash_rlc.cell, tmp_cell.cell())?;

        *offset += 3;
        log::trace!("finished keccak lookup");
        Ok(())
    }

    /// Input the signature data,
    /// Output the cells for byte decomposition of the keys and messages
    fn sign_data_decomposition<'a: 'v, 'v>(
        &self,
        ctx: &mut Context<'v, F>,
        ecdsa_chip: &FpChip<F>,
        sign_data: Option<&SignData>,
        assigned_data: &AssignedECDSA<'v, F, FpChip<F>>,
    ) -> Result<SignDataDecomposed<'a, 'v, F>, Error> {
        // build ecc chip from Fp chip
        let ecc_chip = EccChip::<F, FpChip<F>>::construct(ecdsa_chip.clone());

        let zero = ecdsa_chip.range.gate.load_zero(ctx);

        let (padding, sign_data) = match sign_data {
            Some(sign_data) => (false, sign_data.clone()),
            None => (true, SignData::default()),
        };

        // ================================================
        // step 0. powers of aux parameters
        // ================================================
        let powers_of_256 =
            iter::successors(Some(F::one()), |coeff| Some(F::from(256) * coeff)).take(32);
        let powers_of_256_cells = powers_of_256
            .map(|x| QuantumCell::Constant(x))
            .collect_vec();

        // ================================================
        // pk hash cells
        // ================================================
        let pk_le = pk_bytes_le(&sign_data.pk);
        let pk_be = pk_bytes_swap_endianness(&pk_le);
        let pk_hash = {
            let mut keccak = Keccak::default();
            keccak.update(&pk_be);
            let hash: [_; 32] = keccak.digest().try_into().expect("vec to array of size 32");
            hash
        }
        .map(|byte| Value::known(F::from(byte as u64)));

        log::trace!("pk hash {:0x?}", pk_hash);
        let pk_hash_cells = pk_hash
            .iter()
            .map(|&x| QuantumCell::Witness(x))
            .rev()
            .collect_vec();

        // address is the random linear combination of the public key
        // it is fine to use a phase 1 gate here
        let address = ecdsa_chip.range.gate.inner_product(
            ctx,
            powers_of_256_cells[..20].to_vec(),
            pk_hash_cells[..20].to_vec(),
        );
        log::trace!("address: {:?}", address.value());

        let is_address_zero = ecdsa_chip.range.gate.is_equal(
            ctx,
            QuantumCell::Existing(&address),
            QuantumCell::Existing(&zero),
        );
        let is_address_zero_cell = QuantumCell::Existing(&is_address_zero);

        // ================================================
        // message hash cells
        // ================================================

        let assert_crt = |ctx: &mut Context<F>,
                          bytes: [u8; 32],
                          crt_integer: &CRTInteger<'v, F>,
                          overriding: &Option<&QuantumCell<F>>|
         -> Result<_, Error> {
            //let bytes: [u8; 32] = v.to_bytes();
            let byte_cells: Vec<QuantumCell<F>> = bytes
                .iter()
                .map(|&x| QuantumCell::Witness(Value::known(F::from_u128(x as u128))))
                .collect_vec();

            self.assert_crt_int_byte_repr(
                ctx,
                &ecdsa_chip.range,
                crt_integer,
                &byte_cells,
                &powers_of_256_cells,
                overriding,
            )?;
            Ok(byte_cells)
        };

        // assert the assigned_msg_hash_le is the right decomposition of msg_hash
        // msg_hash is an overflowing integer with 3 limbs, of sizes 88, 88, and 80
        let assigned_msg_hash_le = assert_crt(
            ctx,
            sign_data.msg_hash.to_bytes(),
            &assigned_data.msg_hash,
            &Some(&is_address_zero_cell),
        )?;

        // ================================================
        // pk cells
        // ================================================
        let pk_x_le = sign_data
            .pk
            .x
            .to_bytes()
            .iter()
            .map(|&x| QuantumCell::Witness(Value::known(F::from_u128(x as u128))))
            .collect_vec();

        let pk_y_le = sign_data
            .pk
            .y
            .to_bytes()
            .iter()
            .map(|&x| QuantumCell::Witness(Value::known(F::from_u128(x as u128))))
            .collect_vec();
        let pk_assigned = ecc_chip.load_private(
            ctx,
            (Value::known(sign_data.pk.x), Value::known(sign_data.pk.y)),
        );

        self.assert_crt_int_byte_repr(
            ctx,
            &ecdsa_chip.range,
            &pk_assigned.x,
            &pk_x_le,
            &powers_of_256_cells,
            &None,
        )?;

        self.assert_crt_int_byte_repr(
            ctx,
            &ecdsa_chip.range,
            &pk_assigned.y,
            &pk_y_le,
            &powers_of_256_cells,
            &None,
        )?;

        let assigned_pk_le_selected = [pk_y_le, pk_x_le].concat();
        log::trace!("finished data decomposition");

        let r_cells = assert_crt(
            ctx,
            sign_data.signature.0.to_bytes(),
            &assigned_data.integer_r,
            &None,
        )?;
        let s_cells = assert_crt(
            ctx,
            sign_data.signature.1.to_bytes(),
            &assigned_data.integer_s,
            &None,
        )?;

        Ok(SignDataDecomposed {
            pk_hash_cells,
            msg_hash_cells: assigned_msg_hash_le,
            pk_cells: assigned_pk_le_selected,
            address,
            is_address_zero,
            r_cells,
            s_cells,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn assign_sig_verify<'a: 'v, 'v>(
        &self,
        ctx: &mut Context<'v, F>,
        rlc_chip: &RangeConfig<F>,
        sign_data: Option<&SignData>,
        sign_data_decomposed: &SignDataDecomposed<'a, 'v, F>,
        challenges: &Challenges<Value<F>>,
        sig_is_valid: &AssignedValue<'v, F>,
    ) -> Result<([AssignedValue<'v, F>; 3], AssignedSignatureVerify<F>), Error> {
        let (_padding, sign_data) = match sign_data {
            Some(sign_data) => (false, sign_data.clone()),
            None => (true, SignData::default()),
        };

        // ================================================
        // step 0. powers of aux parameters
        // ================================================
        let evm_challenge_powers = iter::successors(Some(Value::known(F::one())), |coeff| {
            Some(challenges.evm_word() * coeff)
        })
        .take(32)
        .map(|x| QuantumCell::Witness(x))
        .collect_vec();

        log::trace!("evm challenge: {:?} ", challenges.evm_word());

        let keccak_challenge_powers = iter::successors(Some(Value::known(F::one())), |coeff| {
            Some(challenges.keccak_input() * coeff)
        })
        .take(64)
        .map(|x| QuantumCell::Witness(x))
        .collect_vec();
        // ================================================
        // step 1 random linear combination of message hash
        // ================================================
        // Ref. spec SignVerifyChip 3. Verify that the signed message in the ecdsa_chip
        // with RLC encoding corresponds to msg_hash_rlc
        let msg_hash_rlc = rlc_chip.gate.inner_product(
            ctx,
            sign_data_decomposed
                .msg_hash_cells
                .iter()
                .take(32)
                .cloned()
                .collect_vec(),
            evm_challenge_powers.clone(),
        );

        log::trace!("assigned msg hash rlc: {:?}", msg_hash_rlc.value());

        // ================================================
        // step 2 random linear combination of pk
        // ================================================
        let pk_rlc = rlc_chip.gate.inner_product(
            ctx,
            sign_data_decomposed.pk_cells.clone(),
            keccak_challenge_powers,
        );
        log::trace!("pk rlc: {:?}", pk_rlc.value());

        // ================================================
        // step 3 random linear combination of pk_hash
        // ================================================
        let pk_hash_rlc = rlc_chip.gate.inner_product(
            ctx,
            sign_data_decomposed.pk_hash_cells.clone(),
            evm_challenge_powers.clone(),
        );

        // step 4: r,s rlc
        let r_rlc = rlc_chip.gate.inner_product(
            ctx,
            sign_data_decomposed.r_cells.clone(),
            evm_challenge_powers.clone(),
        );
        let s_rlc = rlc_chip.gate.inner_product(
            ctx,
            sign_data_decomposed.s_cells.clone(),
            evm_challenge_powers.clone(),
        );

        log::trace!("pk hash rlc halo2ecc: {:?}", pk_hash_rlc.value());
        log::trace!("finished sign verify");
        let to_be_keccak_checked = [
            sign_data_decomposed.is_address_zero.clone(),
            pk_rlc,
            pk_hash_rlc,
        ];
        let assigned_sig_verif = AssignedSignatureVerify {
            address: sign_data_decomposed.address.clone().into(),
            msg_len: sign_data.msg.len(),
            msg_rlc: challenges
                .keccak_input()
                .map(|r| rlc::value(sign_data.msg.iter().rev(), r)),
            msg_hash_rlc: msg_hash_rlc.into(),
            sig_is_valid: sig_is_valid.clone().into(),
            r_rlc: r_rlc.into(),
            s_rlc: s_rlc.into(),
        };
        Ok((to_be_keccak_checked, assigned_sig_verif))
    }

    pub(crate) fn assign(
        &self,
        config: &SigCircuitConfig<F>,
        layouter: &mut impl Layouter<F>,
        signatures: &[SignData],
        challenges: &Challenges<Value<F>>,
    ) -> Result<Vec<AssignedSignatureVerify<F>>, Error> {
        if signatures.len() > self.max_verif {
            error!(
                "signatures.len() = {} > max_verif = {}",
                signatures.len(),
                self.max_verif
            );
            return Err(Error::Synthesis);
        }
        let mut first_pass = SKIP_FIRST_PASS;
        let ecdsa_chip = &config.ecdsa_config;

        let assigned_sig_verifs = layouter.assign_region(
            || "ecdsa chip verification",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(vec![]);
                }

                let mut ctx = ecdsa_chip.new_context(region);

                // ================================================
                // step 0: assert the signature is valid in circuit
                // ================================================
                let mut assigned_ecdsas = Vec::new();

                for i in 0..self.max_verif {
                    let signature = if i < signatures.len() {
                        signatures[i].clone()
                    } else {
                        // padding (enabled when address == 0)
                        SignData::default()
                    };
                    let assigned_ecdsa = self.assign_ecdsa(&mut ctx, ecdsa_chip, &signature)?;
                    assigned_ecdsas.push(assigned_ecdsa);
                }

                // ================================================
                // step 1: decompose the keys and messages
                // ================================================
                let mut sign_data_decomposed_vec = Vec::new();
                for (i, assigned_ecdsa) in assigned_ecdsas.iter().enumerate() {
                    let sign_data = signatures.get(i); // None when padding (enabled when address == 0)
                    let sign_data_decomposed = self.sign_data_decomposition(
                        &mut ctx,
                        ecdsa_chip,
                        sign_data,
                        assigned_ecdsa,
                    )?;
                    sign_data_decomposed_vec.push(sign_data_decomposed);
                }

                // IMPORTANT: Move to Phase2 before RLC
                log::debug!("before proceeding to the next phase");
                ctx.print_stats(&["Range"]);

                #[cfg(not(feature = "onephase"))]
                {
                    // finalize the current lookup table before moving to next phase
                    ecdsa_chip.finalize(&mut ctx);
                    ctx.next_phase();
                }

                // ================================================
                // step 3: compute RLC of keys and messages
                // ================================================
                let mut assigned_sig_verifs: Vec<AssignedSignatureVerify<F>> = Vec::new();
                let mut deferred_keccak_check = Vec::new();
                for (i, e) in assigned_ecdsas.iter().enumerate() {
                    let sign_data = signatures.get(i); // None when padding (enabled when address == 0)
                    let sign_data_decomposed = &sign_data_decomposed_vec[i];
                    let (to_be_keccak_checked, assigned_sig_verif) = self.assign_sig_verify(
                        &mut ctx,
                        &ecdsa_chip.range,
                        sign_data,
                        sign_data_decomposed,
                        challenges,
                        &e.sig_is_valid,
                    )?;
                    assigned_sig_verifs.push(assigned_sig_verif);
                    deferred_keccak_check.push(to_be_keccak_checked);
                }

                // ================================================
                // step 4: deferred keccak checks
                // ================================================
                let mut offset = 0;
                for e in deferred_keccak_check.iter() {
                    let [is_address_zero, pk_rlc, pk_hash_rlc] = e;
                    self.enable_keccak_lookup(
                        config,
                        &mut ctx,
                        &mut offset,
                        is_address_zero,
                        pk_rlc,
                        pk_hash_rlc,
                    )?;
                }

                // IMPORTANT: this assigns all constants to the fixed columns
                // IMPORTANT: this copies cells to the lookup advice column to perform range
                // check lookups
                // This is not optional.
                let lookup_cells = ecdsa_chip.finalize(&mut ctx);
                log::debug!("total number of lookup cells: {}", lookup_cells);

                ctx.print_stats(&["Range"]);
                Ok(assigned_sig_verifs)
            },
        )?;

        // TODO: is this correct?
        layouter.assign_region(
            || "expose sig table",
            |mut region| {
                // step 5: export as a lookup table
                for (idx, assigned_sig_verif) in assigned_sig_verifs.iter().enumerate() {
                    region.assign_fixed(
                        || "assign sig_table selector",
                        config.sig_table.q_enable,
                        idx,
                        || Value::known(F::one()),
                    )?;

                    // FIXME: constrain v
                    region.assign_advice(
                        || "assign sig_table v",
                        config.sig_table.sig_v,
                        idx,
                        || Value::known(F::from(signatures[idx].signature.2 as u64)),
                    )?;

                    let r_rlc: AssignedValue<_> = assigned_sig_verif.r_rlc.clone().into();
                    r_rlc.copy_advice(&mut region, config.sig_table.sig_r_rlc, idx);

                    let s_rlc: AssignedValue<_> = assigned_sig_verif.s_rlc.clone().into();
                    s_rlc.copy_advice(&mut region, config.sig_table.sig_s_rlc, idx);

                    let address: AssignedValue<_> = assigned_sig_verif.address.clone().into();
                    address.copy_advice(&mut region, config.sig_table.recovered_addr, idx);

                    let is_valid: AssignedValue<_> = assigned_sig_verif.sig_is_valid.clone().into();
                    is_valid.copy_advice(&mut region, config.sig_table.is_valid, idx);

                    let hash_rlc: AssignedValue<_> = assigned_sig_verif.msg_hash_rlc.clone().into();
                    hash_rlc.copy_advice(&mut region, config.sig_table.msg_hash_rlc, idx);
                }
                Ok(())
            },
        )?;

        Ok(assigned_sig_verifs)
    }

    /// Assert an CRTInteger's byte representation is correct.
    /// inputs
    /// - crt_int with 3 limbs [88, 88, 80]
    /// - byte representation of the integer
    /// - a sequence of [1, 2^8, 2^16, ...]
    /// - a overriding flag that sets output to 0 if set
    fn assert_crt_int_byte_repr(
        &self,
        ctx: &mut Context<F>,
        range_chip: &RangeConfig<F>,
        crt_int: &CRTInteger<F>,
        byte_repr: &[QuantumCell<F>],
        powers_of_256: &[QuantumCell<F>],
        overriding: &Option<&QuantumCell<F>>,
    ) -> Result<(), Error> {
        // length of byte representation is 32
        assert_eq!(byte_repr.len(), 32);
        // need to support decomposition of up to 88 bits
        assert!(powers_of_256.len() >= 11);

        let flex_gate_chip = &range_chip.gate;
        let zero = flex_gate_chip.load_zero(ctx);
        let zero_cell = QuantumCell::Existing(&zero);

        // apply the overriding flag
        let limb1_value = match overriding {
            Some(p) => flex_gate_chip.select(
                ctx,
                zero_cell.clone(),
                QuantumCell::Existing(&crt_int.truncation.limbs[0]),
                (*p).clone(),
            ),
            None => crt_int.truncation.limbs[0].clone(),
        };
        let limb2_value = match overriding {
            Some(p) => flex_gate_chip.select(
                ctx,
                zero_cell.clone(),
                QuantumCell::Existing(&crt_int.truncation.limbs[1]),
                (*p).clone(),
            ),
            None => crt_int.truncation.limbs[1].clone(),
        };
        let limb3_value = match overriding {
            Some(p) => flex_gate_chip.select(
                ctx,
                zero_cell,
                QuantumCell::Existing(&crt_int.truncation.limbs[2]),
                (*p).clone(),
            ),
            None => crt_int.truncation.limbs[2].clone(),
        };

        // assert the byte_repr is the right decomposition of overflow_int
        // overflow_int is an overflowing integer with 3 limbs, of sizes 88, 88, and 80
        // we reconstruct the three limbs from the bytes repr, and
        // then enforce equality with the CRT integer
        let limb1_recover = flex_gate_chip.inner_product(
            ctx,
            byte_repr[0..11].to_vec(),
            powers_of_256[0..11].to_vec(),
        );
        let limb2_recover = flex_gate_chip.inner_product(
            ctx,
            byte_repr[11..22].to_vec(),
            powers_of_256[0..11].to_vec(),
        );
        let limb3_recover = flex_gate_chip.inner_product(
            ctx,
            byte_repr[22..].to_vec(),
            powers_of_256[0..10].to_vec(),
        );
        flex_gate_chip.assert_equal(
            ctx,
            QuantumCell::Existing(&limb1_value),
            QuantumCell::Existing(&limb1_recover),
        );
        flex_gate_chip.assert_equal(
            ctx,
            QuantumCell::Existing(&limb2_value),
            QuantumCell::Existing(&limb2_recover),
        );
        flex_gate_chip.assert_equal(
            ctx,
            QuantumCell::Existing(&limb3_value),
            QuantumCell::Existing(&limb3_recover),
        );
        log::trace!(
            "limb 1 \ninput {:?}\nreconstructed {:?}",
            limb1_value.value(),
            limb1_recover.value()
        );
        log::trace!(
            "limb 2 \ninput {:?}\nreconstructed {:?}",
            limb2_value.value(),
            limb2_recover.value()
        );
        log::trace!(
            "limb 3 \ninput {:?}\nreconstructed {:?}",
            limb3_value.value(),
            limb3_recover.value()
        );

        Ok(())
    }
    /*
    pub(crate) fn assert_sig_is_valid(
        &self,
        config: &SigCircuitConfig<F>,
        layouter: &mut impl Layouter<F>,
        sig_verifs: &[AssignedSignatureVerify<F>],
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "ecdsa chip verification",
            |mut region| {
                let one = region.assign_fixed(
                    || "one",
                    config.fixed_column,
                    0,
                    || Value::known(F::one()),
                )?;

                for (i, sig_verif) in sig_verifs.iter().enumerate() {
                    log::trace!(
                        "checking {}-th signature is valid: {:?}",
                        i,
                        sig_verif.sig_is_valid.value
                    );

                    region.constrain_equal(sig_verif.sig_is_valid.cell, one.cell())?;
                }

                Ok(())
            },
        )
    }
    */
}
