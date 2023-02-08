//! Circuit to verify multiple ECDSA secp256k1 signatures.
//
// This module uses two different types of chip configurations
// - halo2-ecc's ecdsa chip, which is used
//    - to prove the correctness of secp signatures
//    - to compute the RLC in circuit
// - halo2wrong's main gate chip: this is used for keccak lookup table
//
//
//
// Naming notes:
// - *_be: Big-Endian bytes
// - *_le: Little-Endian bytes

use crate::{
    evm_circuit::util::{not, rlc},
    table::KeccakTable,
    util::{Challenges, Expr},
};
use ecc::maingate;
use eth_types::sign_types::{pk_bytes_le, pk_bytes_swap_endianness, SignData};
use eth_types::{self, Field};
use halo2_base::{
    gates::{GateInstructions, RangeInstructions as Halo2Range},
    AssignedValue, Context, QuantumCell,
};
use halo2_base::{utils::modulus, ContextParams};
use halo2_ecc::{
    bigint::CRTInteger,
    fields::fp::{FpConfig, FpStrategy},
};
use halo2_ecc::{
    bigint::OverflowInteger,
    ecc::{ecdsa_verify_no_pubkey_check, EccPoint},
    fields::FieldChip,
};
use halo2_ecc::{ecc::EccChip, fields::fp_overflow::FpOverflowChip};
use halo2_proofs::{
    circuit::{Layouter, Value},
    halo2curves::secp256k1::Secp256k1Affine,
    halo2curves::secp256k1::{Fp, Fq},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector},
    poly::Rotation,
};

#[cfg(feature = "onephase")]
use halo2_proofs::plonk::FirstPhase as SecondPhase;
#[cfg(not(feature = "onephase"))]
use halo2_proofs::plonk::SecondPhase;

use itertools::Itertools;
use keccak256::plain::Keccak;
use log::error;
use maingate::{MainGate, MainGateConfig, RegionCtx};
use std::{iter, marker::PhantomData};

// Hard coded parameters.
// FIXME: allow for a configurable param.
const NUM_ADVICE: usize = 36;
// Each ecdsa signature requires 11688  (signature) + 119 (rlc) = 11807 rows
// We set ROWS_PER_SIG = 11850 to allows for a few buffer
const ROWS_PER_SIG: usize = 11850;

/// Chip to handle overflow integers of ECDSA::Fq, the scalar field
type FqOverflowChip<'a, F> = FpOverflowChip<'a, F, Fq>;
/// Chip to handle ECDSA::Fp, the base field
type FpChip<F> = FpConfig<F, Fp>;

/// Auxiliary Gadget to verify a that a message hash is signed by the public
/// key corresponding to an Ethereum Address.
#[derive(Clone, Debug)]
pub struct SignVerifyChip<F: Field> {
    /// Max number of verifications
    pub max_verif: usize,
    /// Marker
    pub _marker: PhantomData<F>,
}

impl<F: Field> SignVerifyChip<F> {
    /// Return a new SignVerifyChip
    pub fn new(max_verif: usize) -> Self {
        Self {
            max_verif,
            _marker: PhantomData,
        }
    }

    /// Return the minimum number of rows required to prove an input of a
    /// particular size.
    pub fn min_num_rows(num_verif: usize) -> usize {
        num_verif * ROWS_PER_SIG
    }
}

impl<F: Field> Default for SignVerifyChip<F> {
    fn default() -> Self {
        Self {
            max_verif: 0,
            _marker: PhantomData::default(),
        }
    }
}

/// SignVerify Configuration
#[derive(Debug, Clone)]
pub(crate) struct SignVerifyConfig<F: Field> {
    // ECDSA
    ecdsa_config: FpChip<F>,
    main_gate_config: MainGateConfig,
    // RLC
    rlc: Column<Advice>,
    // Keccak
    q_keccak: Selector,
    keccak_table: KeccakTable,
}

impl<F: Field> SignVerifyConfig<F> {
    pub(crate) fn new(meta: &mut ConstraintSystem<F>, keccak_table: KeccakTable) -> Self {
        // halo2-ecc's ECDSA config
        //
        // Create a new FpConfig chip for the following parameters
        // {"strategy":"Simple","degree":14,"num_advice":36,"num_lookup_advice":6,"
        // num_fixed":1," lookup_bits":13,"limb_bits":88,"num_limbs":3}
        //
        // - num_advice: 36
        // - num_lookup_advice: 6
        // - num_fixed: 1
        // - lookup_bits: 13
        // - limb_bits: 88
        // - num_limbs: 3
        //
        // TODO: make those parameters tunable from a config file
        let ecdsa_config = FpConfig::configure(
            meta,
            FpStrategy::SimplePlus,
            &[NUM_ADVICE],
            &[13],
            1,
            13,
            88,
            3,
            modulus::<Fp>(),
            "ecdsa chip".to_string(),
        );

        // halo2wrong's main gate config
        let main_gate_config = MainGate::<F>::configure(meta);

        // RLC
        let rlc = meta.advice_column_in(SecondPhase);
        meta.enable_equality(rlc);

        // Ref. spec SignVerifyChip 1. Verify that keccak(pub_key_bytes) = pub_key_hash
        // by keccak table lookup, where pub_key_bytes is built from the pub_key
        // in the ecdsa_chip.
        let q_keccak = meta.complex_selector();
        meta.lookup_any("keccak", |meta| {
            // When address is 0, we disable the signature verification by using a dummy pk,
            // msg_hash and signature which is not constrainted to match msg_hash_rlc nor
            // the address.
            // Layout:
            // | q_keccak |        a        |     rlc     |
            // | -------- | --------------- | ----------- |
            // |     1    | is_address_zero |    pk_rlc   |
            // |          |                 | pk_hash_rlc |
            let q_keccak = meta.query_selector(q_keccak);
            let is_address_zero = meta.query_advice(main_gate_config.advices()[0], Rotation::cur());
            let is_enable = q_keccak * not::expr(is_address_zero);

            let input = [
                is_enable.clone(),
                is_enable.clone() * meta.query_advice(rlc, Rotation::cur()),
                is_enable.clone() * 64usize.expr(),
                is_enable * meta.query_advice(rlc, Rotation::next()),
            ];
            let table = [
                keccak_table.is_enabled,
                keccak_table.input_rlc,
                keccak_table.input_len,
                keccak_table.output_rlc,
            ]
            .map(|column| meta.query_advice(column, Rotation::cur()));

            input.into_iter().zip(table).collect()
        });

        Self {
            ecdsa_config,
            main_gate_config,
            keccak_table,
            rlc,
            q_keccak,
        }
    }
}

impl<F: Field> SignVerifyConfig<F> {
    pub(crate) fn load_range(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.ecdsa_config.range.load_lookup_table(layouter)
    }
}

pub(crate) struct AssignedECDSA<F: Field, FC: FieldChip<F>> {
    pk: EccPoint<F, FC::FieldPoint>,
    msg_hash: OverflowInteger<F>,
    sig_is_valid: AssignedValue<F>,
}

#[derive(Debug)]
pub(crate) struct AssignedSignatureVerify<F: Field> {
    pub(crate) address: AssignedValue<F>,
    pub(crate) msg_len: usize,
    pub(crate) msg_rlc: Value<F>,
    pub(crate) msg_hash_rlc: AssignedValue<F>,
    pub(crate) sig_is_valid: AssignedValue<F>,
}

/// Helper structure pass around references to all the chips required for an
/// ECDSA verification.
struct ChipsRef<'a, F: Field> {
    main_gate: &'a MainGate<F>,
    ecdsa_chip: FpChip<F>,
}

impl<F: Field> SignVerifyChip<F> {
    // Verifies the ecdsa relationship. I.e., prove that the signature
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
    fn assign_ecdsa(
        &self,
        ctx: &mut Context<'_, F>,
        chips: &ChipsRef<F>,
        sign_data: &SignData,
    ) -> Result<AssignedECDSA<F, FpChip<F>>, Error> {
        let SignData {
            signature,
            pk,
            msg: _,
            msg_hash,
        } = sign_data;
        let (sig_r, sig_s) = signature;

        let ChipsRef {
            main_gate: _,
            ecdsa_chip,
        } = chips;

        // build ecc chip from Fp chip
        let ecc_chip = EccChip::<F, FpChip<F>>::construct(ecdsa_chip);
        // build Fq chip from Fp chip
        // TODO: pass the parameters
        let fq_chip = FqOverflowChip::construct(ecdsa_chip.range(), 88, 3, modulus::<Fq>());

        // println!("r: {:?}", sig_r);
        // println!("s: {:?}", sig_s);
        // println!("msg: {:?}", msg_hash);

        let integer_r = fq_chip.load_private(
            ctx,
            FqOverflowChip::<F>::fe_to_witness(&Value::known(*sig_r)),
        )?;
        let integer_s = fq_chip.load_private(
            ctx,
            FqOverflowChip::<F>::fe_to_witness(&Value::known(*sig_s)),
        )?;
        let msg_hash = fq_chip.load_private(
            ctx,
            FqOverflowChip::<F>::fe_to_witness(&Value::known(*msg_hash)),
        )?;

        let pk_assigned = ecc_chip.load_private(ctx, (Value::known(pk.x), Value::known(pk.y)))?;

        // returns the verification result of ecdsa signature
        //
        // WARNING: this circuit does not enforce the returned value to be true
        // make sure the caller checks this result!
        let ecdsa_is_valid = ecdsa_verify_no_pubkey_check::<F, Fp, Fq, Secp256k1Affine>(
            ecc_chip.field_chip,
            ctx,
            &pk_assigned,
            &integer_r,
            &integer_s,
            &msg_hash,
            4,
            4,
        )?;
        // println!("ECDSA res {:?}", ecdsa_is_valid);

        Ok(AssignedECDSA {
            pk: pk_assigned,
            msg_hash,
            sig_is_valid: ecdsa_is_valid,
        })
    }

    fn enable_keccak_lookup(
        &self,
        config: &SignVerifyConfig<F>,
        ctx: &mut RegionCtx<F>,
        is_address_zero: &AssignedValue<F>,
        pk_rlc: &AssignedValue<F>,
        pk_hash_rlc: &AssignedValue<F>,
    ) -> Result<(), Error> {
        let copy = |ctx: &mut RegionCtx<F>, name, column, assigned: &AssignedValue<F>| {
            let copied = ctx.assign_advice(|| name, column, assigned.value().copied())?;
            ctx.constrain_equal(assigned.cell(), copied.cell())?;
            Ok::<_, Error>(())
        };

        let a = config.main_gate_config.advices()[0];
        ctx.enable(config.q_keccak)?;

        copy(ctx, "is_address_zero", a, is_address_zero)?;
        copy(ctx, "pk_rlc", config.rlc, pk_rlc)?;
        ctx.next();
        copy(ctx, "pk_hash_rlc", config.rlc, pk_hash_rlc)?;
        ctx.next();

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn halo2_assign_sig_verify(
        &self,
        ctx: &mut Context<F>,
        chips: &ChipsRef<F>,
        sign_data: Option<&SignData>,
        challenges: &Challenges<Value<F>>,
        sig_is_valid: &AssignedValue<F>,
    ) -> Result<([AssignedValue<F>; 3], AssignedSignatureVerify<F>), Error> {
        let ChipsRef {
            main_gate: _,
            ecdsa_chip,
        } = chips;
        let flex_gate_chip = ecdsa_chip.range.gate.clone();
        let range_chip = ecdsa_chip.range.clone();
        let zero = flex_gate_chip.load_zero(ctx)?;
        let zero_cell = QuantumCell::Existing(&zero);

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

        let evm_challenge_powers = iter::successors(Some(F::one()), |coeff| {
            Some(challenges.evm_word().inner.unwrap() * *coeff)
        })
        .take(32);

        let evm_challenge_powers = evm_challenge_powers
            .map(|x| QuantumCell::Witness(Value::known(x)))
            .collect_vec();

        let keccak_challenge_powers = iter::successors(Some(F::one()), |coeff| {
            Some(challenges.keccak_input().inner.unwrap() * *coeff)
        })
        .take(64);

        let keccak_challenge_powers = keccak_challenge_powers
            .map(|x| QuantumCell::Witness(Value::known(x)))
            .collect_vec();
        // ================================================
        // step 1. convert pk hash into address
        // ================================================
        // Ref. spec SignVerifyChip 2. Verify that the first 20 bytes of the
        // pub_key_hash equal the address

        let pk_le = pk_bytes_le(&sign_data.pk);
        let pk_be = pk_bytes_swap_endianness(&pk_le);
        let pk_hash = (!padding)
            .then(|| {
                let mut keccak = Keccak::default();
                keccak.update(&pk_be);
                let hash: [_; 32] = keccak.digest().try_into().expect("vec to array of size 32");
                hash
            })
            .unwrap_or_default()
            .map(|byte| Value::known(F::from(byte as u64)));

        let pk_hash_cells = pk_hash
            .iter()
            .map(|&x| QuantumCell::Witness(x))
            .rev()
            .collect_vec();

        // address is the random linear combination of the public key
        let (_pk, _, address) = flex_gate_chip.inner_product(
            ctx,
            &powers_of_256_cells[0..20].to_vec(),
            &pk_hash_cells[12..].to_vec(),
        )?;

        let is_address_zero = range_chip.is_equal(
            ctx,
            &QuantumCell::Existing(&address),
            &QuantumCell::Existing(&zero),
        )?;
        let is_address_zero_cell = QuantumCell::Existing(&is_address_zero);
        // println!("pk rlc halo2ecc: {:?}", address.value());

        // ================================================
        // step 2 random linear combination of message hash
        // ================================================
        // Ref. spec SignVerifyChip 3. Verify that the signed message in the ecdsa_chip
        // with RLC encoding corresponds to msg_hash_rlc
        let msg_hash_rlc = {
            let assigned_msg_hash_le = (!padding)
                .then(|| sign_data.msg_hash.to_bytes())
                .unwrap_or_default()
                .iter()
                .map(|&x| QuantumCell::Witness(Value::known(F::from_u128(x as u128))))
                .collect_vec();

            // assert the assigned_msg_hash_le is the right decomposition of msg_hash
            // msg_hash is an overflowing integer with 3 limbs, of sizes 88, 88, and 80
            let assigned_msg_hash = ecdsa_chip.load_private(
                ctx,
                FqOverflowChip::<F>::fe_to_witness(&Value::known(sign_data.msg_hash)),
            )?;

            self.assert_crt_int_byte_repr(
                ctx,
                chips,
                &assigned_msg_hash,
                &assigned_msg_hash_le,
                &powers_of_256_cells,
                &Some(&is_address_zero_cell),
            )?;

            // compute the msg_hash rlc
            let assigned_msg_hash_le_selected = assigned_msg_hash_le
                .iter()
                .map(|byte| flex_gate_chip.select(ctx, &zero_cell, byte, &is_address_zero_cell))
                .collect::<Result<Vec<_>, _>>()?;

            let (_, _, msg_hash_rlc) = flex_gate_chip.inner_product(
                ctx,
                &assigned_msg_hash_le_selected
                    .iter()
                    .map(|x| QuantumCell::Existing(x))
                    .take(32)
                    .collect_vec(),
                &evm_challenge_powers,
            )?;
            msg_hash_rlc
        };
        // println!("halo2ecc assigned msg hash rlc: {:?}", msg_hash_rlc.value());

        // ================================================
        // step 3 random linear combination of pk
        // ================================================
        let pk_rlc = {
            // build ecc chip from Fp chip
            let ecc_chip = EccChip::<F, FpChip<F>>::construct(ecdsa_chip);

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
            )?;

            self.assert_crt_int_byte_repr(
                ctx,
                chips,
                &pk_assigned.x,
                &pk_x_le,
                &powers_of_256_cells,
                &None,
            )?;

            self.assert_crt_int_byte_repr(
                ctx,
                chips,
                &pk_assigned.y,
                &pk_y_le,
                &powers_of_256_cells,
                &None,
            )?;

            // compute the pk rlc
            let assigned_pk_le_selected = [pk_y_le, pk_x_le].concat();

            let (_, _, pk_rlc) = flex_gate_chip.inner_product(
                ctx,
                &assigned_pk_le_selected,
                &keccak_challenge_powers,
            )?;
            // println!("pk rlc halo2ecc: {:?}", pk_rlc.value());
            pk_rlc
        };

        // ================================================
        // step 4 random linear combination of pk_hash
        // ================================================
        let pk_hash_rlc = {
            let (_, _, pk_hash_rlc) =
                flex_gate_chip.inner_product(ctx, &pk_hash_cells, &evm_challenge_powers)?;
            pk_hash_rlc
        };
        // println!("pk hash rlc halo2ecc: {:?}", pk_hash_rlc.value());

        Ok((
            [is_address_zero, pk_rlc, pk_hash_rlc],
            AssignedSignatureVerify {
                address,
                msg_len: sign_data.msg.len(),
                msg_rlc: challenges
                    .keccak_input()
                    .map(|r| rlc::value(sign_data.msg.iter().rev(), r)),
                msg_hash_rlc,
                sig_is_valid: sig_is_valid.clone(),
            },
        ))
    }

    pub(crate) fn assign(
        &self,
        config: &SignVerifyConfig<F>,
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
        let main_gate = MainGate::new(config.main_gate_config.clone());
        let ecdsa_chip = config.ecdsa_config.clone();

        let chips = ChipsRef {
            main_gate: &main_gate,
            ecdsa_chip,
        };

        let assigned_ecdsas = layouter.assign_region(
            || "ecdsa chip verification",
            |region| {
                let mut assigned_ecdsas = Vec::new();
                let mut ctx = Context::new(
                    region,
                    ContextParams {
                        num_advice: vec![("ecdsa chip".to_string(), NUM_ADVICE)],
                    },
                );
                for i in 0..self.max_verif {
                    let signature = if i < signatures.len() {
                        signatures[i].clone()
                    } else {
                        // padding (enabled when address == 0)
                        SignData::default()
                    };
                    let assigned_ecdsa = self.assign_ecdsa(&mut ctx, &chips, &signature)?;
                    assigned_ecdsas.push(assigned_ecdsa);
                }

                // IMPORTANT: this assigns all constants to the fixed columns
                // IMPORTANT: this copies cells to the lookup advice column to perform range
                // check lookups
                // This is not optional.
                let (_const_rows, _total_fixed, _lookup_rows) =
                    chips.ecdsa_chip.finalize(&mut ctx)?;

                Ok(assigned_ecdsas)
            },
        )?;
        let (deferred_keccak_check, assigned_sig_verifs) = layouter.assign_region(
            || "signature address verify",
            |region| {
                let mut assigned_sig_verifs = Vec::new();

                let mut deferred_keccak_check = Vec::new();
                let mut ctx = Context::new(
                    region,
                    ContextParams {
                        num_advice: vec![("ecdsa chip".to_string(), NUM_ADVICE)],
                    },
                );
                for (i, e) in assigned_ecdsas.iter().enumerate() {
                    let sign_data = signatures.get(i); // None when padding (enabled when address == 0)
                    let (to_be_keccak_checked, assigned_sig_verif) = self.halo2_assign_sig_verify(
                        &mut ctx,
                        &chips,
                        sign_data,
                        challenges,
                        &e.sig_is_valid,
                    )?;
                    assigned_sig_verifs.push(assigned_sig_verif);
                    deferred_keccak_check.push(to_be_keccak_checked);
                }
                // let advice_rows = ctx.advice_rows["ecdsa chip"].iter();
                // println!(
                //     "maximum rows used by an advice column: {}",
                //         advice_rows.clone().max().or(Some(&0)).unwrap(),
                // );
                Ok((deferred_keccak_check, assigned_sig_verifs))
            },
        )?;

        layouter.assign_region(
            || "keccak lookup",
            |region| {
                let mut ctx = RegionCtx::new(region, 0);
                for e in deferred_keccak_check.iter() {
                    let [is_address_zero, pk_rlc, pk_hash_rlc] = e;

                    self.enable_keccak_lookup(
                        config,
                        &mut ctx,
                        is_address_zero,
                        pk_rlc,
                        pk_hash_rlc,
                    )?;
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
        chips: &ChipsRef<F>,
        crt_int: &CRTInteger<F>,
        byte_repr: &[QuantumCell<F>],
        powers_of_256: &[QuantumCell<F>],
        overriding: &Option<&QuantumCell<F>>,
    ) -> Result<(), Error> {
        // length of byte representation is 32
        assert_eq!(byte_repr.len(), 32);
        // need to support decomposition of up to 88 bits
        assert!(powers_of_256.len() >= 11);

        let flex_gate_chip = &chips.ecdsa_chip.range.gate;
        let zero = flex_gate_chip.load_zero(ctx)?;
        let zero_cell = QuantumCell::Existing(&zero);

        // apply the overriding flag
        let limb1_value = match overriding {
            Some(p) => flex_gate_chip.select(
                ctx,
                &zero_cell,
                &QuantumCell::Existing(&crt_int.truncation.limbs[0]),
                p,
            )?,
            None => crt_int.truncation.limbs[0].clone(),
        };
        let limb2_value = match overriding {
            Some(p) => flex_gate_chip.select(
                ctx,
                &zero_cell,
                &QuantumCell::Existing(&crt_int.truncation.limbs[1]),
                p,
            )?,
            None => crt_int.truncation.limbs[1].clone(),
        };
        let limb3_value = match overriding {
            Some(p) => flex_gate_chip.select(
                ctx,
                &zero_cell,
                &QuantumCell::Existing(&crt_int.truncation.limbs[2]),
                p,
            )?,
            None => crt_int.truncation.limbs[2].clone(),
        };

        // assert the byte_repr is the right decomposition of overflow_int
        // overflow_int is an overflowing integer with 3 limbs, of sizes 88, 88, and 80
        // we reconstruct the three limbs from the bytes repr, and
        // then enforce equality with the CRT integer
        let (_, _, limb1_recover) = flex_gate_chip.inner_product(
            ctx,
            &byte_repr[0..11].to_vec(),
            &powers_of_256[0..11].to_vec(),
        )?;
        let (_, _, limb2_recover) = flex_gate_chip.inner_product(
            ctx,
            &byte_repr[11..22].to_vec(),
            &powers_of_256[0..11].to_vec(),
        )?;
        let (_, _, limb3_recover) = flex_gate_chip.inner_product(
            ctx,
            &byte_repr[22..].to_vec(),
            &powers_of_256[0..10].to_vec(),
        )?;
        flex_gate_chip.assert_equal(
            ctx,
            &QuantumCell::Existing(&limb1_value),
            &QuantumCell::Existing(&limb1_recover),
        )?;
        flex_gate_chip.assert_equal(
            ctx,
            &QuantumCell::Existing(&limb2_value),
            &QuantumCell::Existing(&limb2_recover),
        )?;
        flex_gate_chip.assert_equal(
            ctx,
            &QuantumCell::Existing(&limb3_value),
            &QuantumCell::Existing(&limb3_recover),
        )?;
        // println!(
        //     "limb 1 \ninput {:?}\nreconstructed {:?}",
        //     limb1_value.value(),
        //     limb1_recover.value()
        // );
        // println!(
        //     "limb 2 \ninput {:?}\nreconstructed {:?}",
        //     limb2_value.value(),
        //     limb2_recover.value()
        // );
        // println!(
        //     "limb 3 \ninput {:?}\nreconstructed {:?}",
        //     limb3_value.value(),
        //     limb3_recover.value()
        // );

        Ok(())
    }

    pub(crate) fn assert_sig_is_valid(
        &self,
        config: &SignVerifyConfig<F>,
        layouter: &mut impl Layouter<F>,
        sig_verifs: &[AssignedSignatureVerify<F>],
    ) -> Result<(), Error> {
        let flex_gate_chip = &config.ecdsa_config.range.gate;

        layouter.assign_region(
            || "assert sigs are valid",
            |region| {
                let mut ctx = Context::new(
                    region,
                    ContextParams {
                        num_advice: vec![("ecdsa chip".to_string(), NUM_ADVICE)],
                    },
                );
                for sig_verif in sig_verifs {
                    flex_gate_chip.assert_is_const(&mut ctx, &sig_verif.sig_is_valid, F::one());
                }
                flex_gate_chip.finalize(&mut ctx)?;

                Ok(())
            },
        )
    }
}

pub(crate) fn pub_key_hash_to_address<F: Field>(pk_hash: &[u8]) -> F {
    pk_hash[32 - 20..]
        .iter()
        .fold(F::zero(), |acc, b| acc * F::from(256) + F::from(*b as u64))
}

#[cfg(test)]
mod sign_verify_tests {
    use super::*;
    use crate::util::Challenges;
    use bus_mapping::circuit_input_builder::keccak_inputs_sign_verify;
    use eth_types::sign_types::sign;
    use halo2_proofs::arithmetic::Field as HaloField;
    use halo2_proofs::halo2curves::secp256k1;
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        halo2curves::{bn256::Fr, group::Curve},
        plonk::Circuit,
    };
    use pretty_assertions::assert_eq;
    use rand::{Rng, RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use sha3::{Digest, Keccak256};

    #[derive(Clone, Debug)]
    struct TestCircuitSignVerifyConfig<F: Field> {
        sign_verify: SignVerifyConfig<F>,
        challenges: Challenges,
    }

    impl<F: Field> TestCircuitSignVerifyConfig<F> {
        pub(crate) fn new(meta: &mut ConstraintSystem<F>) -> Self {
            let keccak_table = KeccakTable::construct(meta);
            let challenges = Challenges::construct(meta);

            let sign_verify = SignVerifyConfig::new(meta, keccak_table);

            TestCircuitSignVerifyConfig {
                sign_verify,
                challenges,
            }
        }
    }

    #[derive(Default)]
    struct TestCircuitSignVerify<F: Field> {
        sign_verify: SignVerifyChip<F>,
        signatures: Vec<SignData>,
    }

    impl<F: Field> Circuit<F> for TestCircuitSignVerify<F> {
        type Config = TestCircuitSignVerifyConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            TestCircuitSignVerifyConfig::new(meta)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let challenges = config.challenges.values(&mut layouter);
            self.sign_verify.assign(
                &config.sign_verify,
                &mut layouter,
                &self.signatures,
                &challenges,
            )?;
            config.sign_verify.keccak_table.dev_load(
                &mut layouter,
                &keccak_inputs_sign_verify(&self.signatures),
                &challenges,
            )?;
            config.sign_verify.load_range(&mut layouter)?;
            Ok(())
        }
    }

    fn run<F: Field>(k: u32, max_verif: usize, signatures: Vec<SignData>) {
        // SignVerifyChip -> ECDSAChip -> MainGate instance column
        let circuit = TestCircuitSignVerify::<F> {
            sign_verify: SignVerifyChip {
                max_verif,
                _marker: PhantomData,
            },
            signatures,
        };

        let prover = match MockProver::run(k, &circuit, vec![vec![]]) {
            Ok(prover) => prover,
            Err(e) => panic!("{:#?}", e),
        };
        assert_eq!(prover.verify(), Ok(()));
    }

    // Generate a test key pair
    fn gen_key_pair(rng: impl RngCore) -> (secp256k1::Fq, Secp256k1Affine) {
        // generate a valid signature
        let generator = Secp256k1Affine::generator();
        let sk = secp256k1::Fq::random(rng);
        let pk = generator * sk;
        let pk = pk.to_affine();

        (sk, pk)
    }

    // Generate a test message hash
    fn gen_msg_hash(rng: impl RngCore) -> secp256k1::Fq {
        secp256k1::Fq::random(rng)
    }

    // Generate a test message.
    fn gen_msg(mut rng: impl RngCore) -> Vec<u8> {
        let msg_len: usize = rng.gen_range(0..128);
        let mut msg = vec![0; msg_len];
        rng.fill_bytes(&mut msg);
        msg
    }

    // Returns (r, s)
    fn sign_with_rng(
        rng: impl RngCore,
        sk: secp256k1::Fq,
        msg_hash: secp256k1::Fq,
    ) -> (secp256k1::Fq, secp256k1::Fq) {
        let randomness = secp256k1::Fq::random(rng);
        sign(randomness, sk, msg_hash)
    }

    #[test]
    fn sign_verify() {
        // Vectors using `XorShiftRng::seed_from_u64(1)`
        // sk: 0x771bd7bf6c6414b9370bb8559d46e1cedb479b1836ea3c2e59a54c343b0d0495
        // pk: (
        //   0x8e31a3586d4c8de89d4e0131223ecfefa4eb76215f68a691ae607757d6256ede,
        //   0xc76fdd462294a7eeb8ff3f0f698eb470f32085ba975801dbe446ed8e0b05400b
        // )
        // pk_hash: d90e2e9d267cbcfd94de06fa7adbe6857c2c733025c0b8938a76beeefc85d6c7
        // addr: 0x7adbe6857c2c733025c0b8938a76beeefc85d6c7
        let mut rng = XorShiftRng::seed_from_u64(1);
        const MAX_VERIF: usize = 3;
        const NUM_SIGS: usize = 2;
        let mut signatures = Vec::new();
        for _ in 0..NUM_SIGS {
            let (sk, pk) = gen_key_pair(&mut rng);
            let msg = gen_msg(&mut rng);
            let msg_hash: [u8; 32] = Keccak256::digest(&msg)
                .as_slice()
                .to_vec()
                .try_into()
                .expect("hash length isn't 32 bytes");
            let msg_hash = secp256k1::Fq::from_bytes(&msg_hash).unwrap();
            let sig = sign_with_rng(&mut rng, sk, msg_hash);
            signatures.push(SignData {
                signature: sig,
                pk,
                msg: msg.into(),
                msg_hash,
            });
        }

        let k = 19;
        run::<Fr>(k, MAX_VERIF, signatures);
    }
}
