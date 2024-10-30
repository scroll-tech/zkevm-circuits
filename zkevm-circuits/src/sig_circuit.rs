//! Circuit to verify multiple ECDSA secp256k1 and secp256r1 signatures.
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
    evm_circuit::{
        util::{not, rlc},
        EvmCircuit,
    },
    keccak_circuit::KeccakCircuit,
    sig_circuit::{ecdsa::ecdsa_verify_no_pubkey_check, utils::*},
    table::{KeccakTable, SigTable},
    util::{Challenges, Expr, Field, SubCircuit, SubCircuitConfig},
};
use eth_types::{
    self,
    sign_types::{pk_bytes_le_generic, pk_bytes_swap_endianness, SignData},
};
use ff::PrimeField;
use halo2_base::{
    gates::{range::RangeConfig, GateInstructions, RangeInstructions},
    utils::{modulus, CurveAffineExt},
    AssignedValue, Context, QuantumCell, SKIP_FIRST_PASS,
};

use halo2_ecc::{
    bigint::CRTInteger,
    ecc::EccChip,
    fields::{fp::FpConfig, FieldChip},
};
use halo2_proofs::arithmetic::CurveAffine;

mod ecdsa;
mod utils;
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
pub(crate) use utils::*;

use halo2_proofs::{
    circuit::{Layouter, Value},
    // secp256k1 curve
    halo2curves::secp256k1::{Fp as Fp_K1, Fq as Fq_K1, Secp256k1Affine},
    // p256 curve
    halo2curves::secp256r1::{Fp as Fp_R1, Fq as Fq_R1, Secp256r1Affine},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

use halo2_base::gates::range::RangeStrategy;

use ethers_core::utils::keccak256;
use itertools::Itertools;
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
    /// secp256k1
    ecdsa_k1_config: FpChipK1<F>,
    /// secp256r1
    ecdsa_r1_config: FpChipR1<F>,
    /// An advice column to store RLC witnesses
    rlc_column: Column<Advice>,
    /// selector for keccak lookup table
    q_keccak: Selector,
    /// Used to lookup pk->pk_hash(addr)
    keccak_table: KeccakTable,
    /// The exposed table to be used by tx circuit and ecrecover
    sig_table: SigTable,
}

const LIMB_BITS: usize = 88;
const NUM_LIMBS: usize = 3;

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
        let max_num_sig = MAX_NUM_SIG_K1 + MAX_NUM_SIG_R1;
        #[cfg(feature = "onephase")]
        let num_advice = [calc_required_advices(max_num_sig)];
        #[cfg(not(feature = "onephase"))]
        // need an additional phase 2 column/basic gate to hold the witnesses during RLC
        // computations
        let num_advice = [calc_required_advices(max_num_sig), 1];

        let num_lookup_advice = [calc_required_lookup_advices(max_num_sig)];

        #[cfg(feature = "onephase")]
        log::info!("configuring ECDSA chip with single phase");
        #[cfg(not(feature = "onephase"))]
        log::info!("configuring ECDSA chip with multiple phases");

        // halo2-ecc's ECDSA config
        //
        // get the following parameters by running
        // `cargo test --release --package zkevm-circuits --lib sig_circuit::test::sign_verify --
        // --nocapture`
        // - num_advice: 56
        // - num_lookup_advice: 8
        // - num_fixed: 1
        // - lookup_bits: 19
        // - limb_bits: 88
        // - num_limbs: 3
        //
        // TODO: make those parameters tunable from a config file

        let range = RangeConfig::<F>::configure(
            meta,
            RangeStrategy::Vertical,
            &num_advice,
            &num_lookup_advice,
            1,
            LOG_TOTAL_NUM_ROWS - 1,
            0,
            LOG_TOTAL_NUM_ROWS,
        );

        let ecdsa_k1_config =
            FpConfig::construct(range.clone(), LIMB_BITS, NUM_LIMBS, modulus::<Fp_K1>());
        let ecdsa_r1_config = FpConfig::construct(range, LIMB_BITS, NUM_LIMBS, modulus::<Fp_R1>());

        // we need one phase 2 column to store RLC results
        #[cfg(feature = "onephase")]
        let rlc_column = meta.advice_column_in(halo2_proofs::plonk::FirstPhase);
        #[cfg(not(feature = "onephase"))]
        let rlc_column = meta.advice_column_in(halo2_proofs::plonk::SecondPhase);

        meta.enable_equality(rlc_column);

        meta.enable_equality(sig_table.recovered_addr);
        meta.enable_equality(sig_table.sig_r_rlc);
        meta.enable_equality(sig_table.sig_s_rlc);
        meta.enable_equality(sig_table.sig_v);
        meta.enable_equality(sig_table.is_valid);
        meta.enable_equality(sig_table.msg_hash_rlc);

        // Ref. spec SignVerifyChip 1. Verify that keccak(pub_key_bytes) = pub_key_hash
        // by keccak table lookup, where pub_key_bytes is built from the pub_key
        // in the ecdsa_chip. it is applicable to both k1 & r1 signatures.
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
            ecdsa_k1_config,
            ecdsa_r1_config,
            rlc_column,
            q_keccak,
            keccak_table,
            sig_table,
        }
    }
}

impl<F: Field> SigCircuitConfig<F> {
    pub(crate) fn load_range(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        // two chips use one `range` config, just load once
        self.ecdsa_r1_config.range.load_lookup_table(layouter)
        //self.ecdsa_k1_config.range.load_lookup_table(layouter)
    }
}

/// Verify a message hash is signed by the public
/// key corresponding to an Ethereum Address.
#[derive(Clone, Debug, Default)]
pub struct SigCircuit<F: Field> {
    /// Max number of k1 sig verifications
    pub max_verify_k1: usize,
    /// Max number of r1 sig verifications
    pub max_verify_r1: usize,
    /// Without padding Secp256k1 signatures
    pub signatures_k1: Vec<SignData<Fq_K1, Secp256k1Affine>>,
    /// Without padding Secp256r1 signatures
    pub signatures_r1: Vec<SignData<Fq_R1, Secp256r1Affine>>,
    /// Marker
    pub _marker: PhantomData<F>,
}

impl<F: Field> SubCircuit<F> for SigCircuit<F> {
    type Config = SigCircuitConfig<F>;

    fn new_from_block(block: &crate::witness::Block) -> Self {
        assert!(block.circuits_params.max_txs <= MAX_NUM_SIG_K1);

        SigCircuit {
            max_verify_k1: MAX_NUM_SIG_K1,
            max_verify_r1: MAX_NUM_SIG_R1,
            signatures_k1: block.get_sign_data(true),
            signatures_r1: block.get_sign_data_p256(true, MAX_NUM_SIG_R1),
            _marker: Default::default(),
        }
    }

    /// Returns number of unusable rows of the SubCircuit, which should be
    /// `meta.blinding_factors() + 1`.
    fn unusable_rows() -> usize {
        [
            KeccakCircuit::<F>::unusable_rows(),
            EvmCircuit::<F>::unusable_rows(),
            // may include additional subcircuits here
        ]
        .into_iter()
        .max()
        .unwrap()
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        // only initialize one RangeConfig which two chips (r1 & k1) shares
        //config.ecdsa_k1_config.range.load_lookup_table(layouter)?;
        config.ecdsa_r1_config.range.load_lookup_table(layouter)?;

        // assign both k1 and r1 signatures
        self.assign(
            config,
            layouter,
            &self.signatures_k1,
            &self.signatures_r1,
            challenges,
        )?;

        Ok(())
    }

    // Since sig circuit / halo2-lib use veticle cell assignment,
    // so the returned pair is consisted of same values
    fn min_num_rows_block(block: &crate::witness::Block) -> (usize, usize) {
        let row_num = if block.circuits_params.max_vertical_circuit_rows == 0 {
            Self::min_num_rows()
        } else {
            block.circuits_params.max_vertical_circuit_rows
        };

        let ecdsa_verif_k1_count = block
            .txs
            .iter()
            .filter(|tx| !tx.tx_type.is_l1_msg())
            .count()
            + block.precompile_events.get_ecrecover_events().len();

        let ecdsa_verif_r1_count = block.precompile_events.get_p256_verify_events().len();

        // Reserve one ecdsa verification for padding tx such that the bad case in which some tx
        // calls MAX_NUM_SIG - 1 ecrecover precompile won't happen. If that case happens, the sig
        // circuit won't have more space for the padding tx's ECDSA verification. Then the
        // prover won't be able to produce any valid proof.
        let max_num_verify_k1 = MAX_NUM_SIG_K1 - 1;
        let max_num_verify_r1 = MAX_NUM_SIG_R1 - 1;

        // Instead of showing actual minimum row usage,
        // halo2-lib based circuits use min_row_num to represent a percentage of total-used capacity
        // This functionality allows l2geth to decide if additional ops can be added.

        let min_row_num = [
            (row_num / max_num_verify_k1) * ecdsa_verif_k1_count,
            (row_num / max_num_verify_r1) * ecdsa_verif_r1_count,
        ]
        .into_iter()
        .max()
        .unwrap();

        (min_row_num, row_num)
    }
}

impl<F: Field> SigCircuit<F> {
    /// Return a new SigCircuit
    pub fn new(max_verify_k1: usize, max_verify_r1: usize) -> Self {
        Self {
            max_verify_k1,
            max_verify_r1,
            signatures_k1: Vec::new(),
            signatures_r1: Vec::new(),
            _marker: PhantomData,
        }
    }

    /// Return the minimum number of rows required to prove an input of a
    /// particular size.
    pub fn min_num_rows() -> usize {
        // SigCircuit can't determine usable rows independently.
        // Instead, the blinding area is determined by other advise columns with most counts of
        // rotation queries. This value is typically determined by either the Keccak or EVM
        // circuit.

        // the cells are allocated vertically, i.e., given a TOTAL_NUM_ROWS * NUM_ADVICE
        // matrix, the allocator will try to use all the cells in the first column, then
        // the second column, etc.

        let max_blinding_factor = Self::unusable_rows() - 1;

        // same formula as halo2-lib's FlexGate
        (1 << LOG_TOTAL_NUM_ROWS) - (max_blinding_factor + 3)
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
    fn assign_ecdsa(
        &self,
        ctx: &mut Context<F>,
        ecdsa_chip: &FpChipK1<F>,
        sign_data: &SignData<Fq_K1, Secp256k1Affine>,
    ) -> Result<AssignedECDSA<F, FpChipK1<F>>, Error> {
        let gate = ecdsa_chip.gate();
        let zero = gate.load_zero(ctx);

        let SignData {
            signature,
            pk,
            msg: _,
            msg_hash,
        } = sign_data;
        let (sig_r, sig_s, v) = signature;

        // build ecc chip from Fp chip
        let ecc_chip = EccChip::<F, FpChipK1<F>>::construct(ecdsa_chip.clone());
        let pk_assigned = ecc_chip.load_private(ctx, (Value::known(pk.x), Value::known(pk.y)));
        let pk_is_valid = ecc_chip.is_on_curve_or_infinity::<Secp256k1Affine>(ctx, &pk_assigned);
        gate.assert_is_const(ctx, &pk_is_valid, F::one());

        // build Fq chip from Fp chip
        let fq_chip = FqChipK1::construct(
            ecdsa_chip.range.clone(),
            LIMB_BITS,
            NUM_LIMBS,
            modulus::<Fq_K1>(),
        );
        let integer_r =
            fq_chip.load_private(ctx, FqChipK1::<F>::fe_to_witness(&Value::known(*sig_r)));
        let integer_s =
            fq_chip.load_private(ctx, FqChipK1::<F>::fe_to_witness(&Value::known(*sig_s)));
        let msg_hash =
            fq_chip.load_private(ctx, FqChipK1::<F>::fe_to_witness(&Value::known(*msg_hash)));

        // returns the verification result of ecdsa signature
        //
        // WARNING: this circuit does not enforce the returned value to be true
        // make sure the caller checks this result!
        let (sig_is_valid, pk_is_zero, y_coord) =
            ecdsa_verify_no_pubkey_check::<F, Fp_K1, Fq_K1, Secp256k1Affine>(
                &ecc_chip.field_chip,
                ctx,
                &pk_assigned,
                &integer_r,
                &integer_s,
                &msg_hash,
                4,
                4,
            );

        // =======================================
        // constrains v == y.is_oddness()
        // =======================================
        assert!(*v == 0 || *v == 1, "v is not boolean");

        // we constrain:
        // - v + 2*tmp = y where y is already range checked (88 bits)
        // - v is a binary
        // - tmp is also < 88 bits (this is crucial otherwise tmp may wrap around and break
        //   soundness)

        let assigned_y_is_odd = gate.load_witness(ctx, Value::known(F::from(*v as u64)));
        gate.assert_bit(ctx, assigned_y_is_odd);

        // the last 88 bits of y
        let assigned_y_limb = &y_coord.limbs()[0];
        let mut y_value = F::zero();
        assigned_y_limb.value().map(|&x| y_value = x);

        // y_tmp = (y_value - y_last_bit)/2
        let y_tmp = (y_value - F::from(*v as u64)) * F::TWO_INV;
        let assigned_y_tmp = gate.load_witness(ctx, Value::known(y_tmp));

        // y_tmp_double = (y_value - y_last_bit)
        let y_tmp_double = gate.mul(
            ctx,
            QuantumCell::Existing(assigned_y_tmp),
            QuantumCell::Constant(F::from(2)),
        );
        let y_rec = gate.add(
            ctx,
            QuantumCell::Existing(y_tmp_double),
            QuantumCell::Existing(assigned_y_is_odd),
        );
        let y_is_ok = gate.is_equal(
            ctx,
            QuantumCell::Existing(*assigned_y_limb),
            QuantumCell::Existing(y_rec),
        );

        // last step we want to constrain assigned_y_tmp is 87 bits
        let assigned_y_tmp = gate.select(
            ctx,
            QuantumCell::Existing(zero),
            QuantumCell::Existing(assigned_y_tmp),
            QuantumCell::Existing(pk_is_zero),
        );
        ecc_chip
            .field_chip
            .range
            .range_check(ctx, &assigned_y_tmp, LIMB_BITS - 1);

        let pk_not_zero = gate.not(ctx, QuantumCell::Existing(pk_is_zero));
        let sig_is_valid = gate.and_many(
            ctx,
            vec![
                QuantumCell::Existing(sig_is_valid),
                QuantumCell::Existing(y_is_ok),
                QuantumCell::Existing(pk_not_zero),
            ],
        );

        Ok(AssignedECDSA {
            pk: pk_assigned,
            pk_is_zero,
            msg_hash,
            integer_r,
            integer_s,
            v: assigned_y_is_odd,
            sig_is_valid,
        })
    }

    // this method try to support both Secp256k1 and Secp256r1 by using generic type.
    // FpChip: can be FpChipK1 or FpChipR1
    // Fq: can be Fq_K1 or Fq_R1
    // Affine can be Secp256k1Affine or Secp256r1Affine
    fn assign_ecdsa_generic<
        Fp: PrimeField<Repr = [u8; 32]> + halo2_base::utils::ScalarField,
        Fq: PrimeField<Repr = [u8; 32]> + halo2_base::utils::ScalarField,
        Affine: CurveAffine<Base = Fp, ScalarExt = Fq> + CurveAffineExt,
    >(
        &self,
        ctx: &mut Context<F>,
        ecdsa_chip: &FpConfig<F, Fp>,
        sign_data: &SignData<Fq, Affine>,
    ) -> Result<AssignedECDSA<F, FpConfig<F, Fp>>, Error>
    where
        Affine::Base: ff::PrimeField,
    {
        let gate = ecdsa_chip.gate();

        let SignData {
            signature,
            pk,
            msg: _,
            msg_hash,
        } = sign_data;
        let (sig_r, sig_s, v) = signature;

        // build ecc chip from Fp chip
        let ecc_chip = EccChip::<F, FpConfig<F, Fp>>::construct(ecdsa_chip.clone());

        let (x, y) = pk.into_coordinates();
        let pk_assigned = ecc_chip.load_private(ctx, (Value::known(x), Value::known(y)));
        let pk_is_valid = ecc_chip.is_on_curve_or_infinity::<Affine>(ctx, &pk_assigned);
        gate.assert_is_const(ctx, &pk_is_valid, F::one());

        // build Fq chip from Fp chip
        let fq_chip = FpConfig::<F, Fq>::construct(
            ecdsa_chip.range().clone(),
            LIMB_BITS,
            NUM_LIMBS,
            modulus::<Fq>(),
        );
        let integer_r =
            fq_chip.load_private(ctx, FpConfig::<F, Fq>::fe_to_witness(&Value::known(*sig_r)));
        let integer_s =
            fq_chip.load_private(ctx, FpConfig::<F, Fq>::fe_to_witness(&Value::known(*sig_s)));
        let msg_hash = fq_chip.load_private(
            ctx,
            FpConfig::<F, Fq>::fe_to_witness(&Value::known(*msg_hash)),
        );

        // returns the verification result of ecdsa signature
        //
        // WARNING: this circuit does not enforce the returned value to be true
        // make sure the caller checks this result!
        let (sig_is_valid, pk_is_zero, y_coord) =
            // `ecdsa_verify_no_pubkey_check`can verify p256 constraints now after fix halo2-ecc issue
            ecdsa_verify_no_pubkey_check::<F, Fp, Fq, Affine>(
                &ecc_chip.field_chip,
                ctx,
                &pk_assigned,
                &integer_r,
                &integer_s,
                &msg_hash,
                4,
                4,
            );

        // =======================================
        // constrains v == y.is_oddness()
        // =======================================
        assert!(*v == 0 || *v == 1, "v is not boolean");

        let pk_not_zero = gate.not(ctx, QuantumCell::Existing(pk_is_zero));

        // check if p256 curve, for precompile p256Verify, there is no need of v in the input data
        // and just use public key (x, y) provided instead.
        // so only secp256k1 signature data need to check v oddness
        let (sig_is_valid, assigned_y_is_odd) = if self.is_k1_sig::<Fp, Affine>() {
            let (y_is_ok, assigned_y_is_odd) =
                self.check_y_oddness(ctx, ecdsa_chip, v, y_coord, pk_is_zero);
            let sig_is_valid = gate.and_many(
                ctx,
                vec![
                    QuantumCell::Existing(sig_is_valid),
                    QuantumCell::Existing(y_is_ok),
                    QuantumCell::Existing(pk_not_zero),
                ],
            );

            (sig_is_valid, assigned_y_is_odd)
        } else {
            let sig_is_valid = gate.and_many(
                ctx,
                vec![
                    QuantumCell::Existing(sig_is_valid),
                    QuantumCell::Existing(pk_not_zero),
                ],
            );

            // for p256, don't use `assigned_y_is_odd` field, zero as placeholder.
            (sig_is_valid, gate.load_zero(ctx)) // cache zero ?
        };

        Ok(AssignedECDSA {
            pk: pk_assigned,
            pk_is_zero,
            msg_hash,
            integer_r,
            integer_s,
            v: assigned_y_is_odd,
            sig_is_valid,
        })
    }

    // check if secp256k1 sig.
    fn is_k1_sig<
        Fp: PrimeField<Repr = [u8; 32]> + halo2_base::utils::ScalarField,
        Affine: CurveAffine<Base = Fp>,
    >(
        &self,
    ) -> bool {
        Affine::a() == Fp::ZERO
    }

    // check v and y oddness relation for secp2256k1
    fn check_y_oddness<Fp: PrimeField<Repr = [u8; 32]> + halo2_base::utils::ScalarField>(
        &self,
        ctx: &mut Context<F>,
        ecdsa_chip: &FpConfig<F, Fp>,
        v: &u8,
        y_coord: CRTInteger<F>,
        pk_is_zero: AssignedValue<F>,
    ) -> (AssignedValue<F>, AssignedValue<F>) {
        // we constrain:
        // - v + 2*tmp = y where y is already range checked (88 bits)
        // - v is a binary
        // - tmp is also < 88 bits (this is crucial otherwise tmp may wrap around and break
        //   soundness)
        let gate = ecdsa_chip.gate();
        let zero = gate.load_zero(ctx);

        let assigned_y_is_odd = gate.load_witness(ctx, Value::known(F::from(*v as u64)));
        gate.assert_bit(ctx, assigned_y_is_odd);

        // the last 88 bits of y
        let assigned_y_limb = &y_coord.limbs()[0];
        let mut y_value = F::zero();
        assigned_y_limb.value().map(|&x| y_value = x);

        // y_tmp = (y_value - y_last_bit)/2
        let y_tmp = (y_value - F::from(*v as u64)) * F::TWO_INV;
        let assigned_y_tmp = gate.load_witness(ctx, Value::known(y_tmp));

        // y_tmp_double = (y_value - y_last_bit)
        let y_tmp_double = gate.mul(
            ctx,
            QuantumCell::Existing(assigned_y_tmp),
            QuantumCell::Constant(F::from(2)),
        );
        let y_rec = gate.add(
            ctx,
            QuantumCell::Existing(y_tmp_double),
            QuantumCell::Existing(assigned_y_is_odd),
        );
        let y_is_ok = gate.is_equal(
            ctx,
            QuantumCell::Existing(*assigned_y_limb),
            QuantumCell::Existing(y_rec),
        );

        // last step we want to constrain assigned_y_tmp is 87 bits
        let assigned_y_tmp = gate.select(
            ctx,
            QuantumCell::Existing(zero),
            QuantumCell::Existing(assigned_y_tmp),
            QuantumCell::Existing(pk_is_zero),
        );

        //let ecc_chip = EccChip::<F, FpChipK1<F>>::construct(ecdsa_chip.clone());

        let ecc_chip = EccChip::construct(ecdsa_chip.clone());
        ecc_chip
            .field_chip
            .range
            .range_check(ctx, &assigned_y_tmp, LIMB_BITS - 1);

        (y_is_ok, assigned_y_is_odd)
    }

    fn enable_keccak_lookup(
        &self,
        config: &SigCircuitConfig<F>,
        ctx: &mut Context<F>,
        offset: usize,
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
        config.q_keccak.enable(&mut ctx.region, offset)?;

        // is_address_zero
        let tmp_cell = ctx.region.assign_advice(
            || "is_address_zero",
            config.rlc_column,
            offset,
            || is_address_zero.value,
        )?;
        ctx.region
            .constrain_equal(is_address_zero.cell, tmp_cell.cell())?;

        // pk_rlc
        let tmp_cell = ctx.region.assign_advice(
            || "pk_rlc",
            config.rlc_column,
            offset + 1,
            || pk_rlc.value,
        )?;
        ctx.region.constrain_equal(pk_rlc.cell, tmp_cell.cell())?;

        // pk_hash_rlc
        let tmp_cell = ctx.region.assign_advice(
            || "pk_hash_rlc",
            config.rlc_column,
            offset + 2,
            || pk_hash_rlc.value,
        )?;
        ctx.region
            .constrain_equal(pk_hash_rlc.cell, tmp_cell.cell())?;

        log::trace!("finished keccak lookup");
        Ok(())
    }

    // this helper aims to handle both k1 and r1 signatures by generic type.
    fn sign_data_decomposition_generic<
        Fp: PrimeField<Repr = [u8; 32]> + halo2_base::utils::ScalarField,
        Fq: PrimeField<Repr = [u8; 32]> + halo2_base::utils::ScalarField,
        Affine: CurveAffine<Base = Fp, ScalarExt = Fq> + CurveAffineExt,
    >(
        &self,
        ctx: &mut Context<F>,
        ecdsa_chip: &FpConfig<F, Fp>,
        sign_data: &SignData<Fq, Affine>,
        assigned_data: &AssignedECDSA<F, FpConfig<F, Fp>>,
    ) -> Result<SignDataDecomposed<F>, Error>
    where
        Affine::Base: ff::PrimeField,
    {
        // build ecc chip from Fp chip
        let ecc_chip = EccChip::<F, FpConfig<F, Fp>>::construct(ecdsa_chip.clone());

        let zero = ecdsa_chip.range.gate.load_zero(ctx);

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
        let pk_le = pk_bytes_le_generic(&sign_data.pk);
        let pk_be = pk_bytes_swap_endianness(&pk_le);
        // keccak p256 pk seems not a problem.
        let pk_hash = keccak256(pk_be).map(|byte| Value::known(F::from(byte as u64)));

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
        let address = ecdsa_chip.range.gate.select(
            ctx,
            QuantumCell::Existing(zero),
            QuantumCell::Existing(address),
            QuantumCell::Existing(assigned_data.pk_is_zero),
        );
        let is_address_zero = ecdsa_chip.range.gate.is_equal(
            ctx,
            QuantumCell::Existing(address),
            QuantumCell::Existing(zero),
        );
        log::trace!("address: {:?}", address.value());

        // ================================================
        // message hash cells
        // ================================================

        let assert_crt = |ctx: &mut Context<F>,
                          bytes: [u8; 32],
                          crt_integer: &CRTInteger<F>|
         -> Result<_, Error> {
            let byte_cells: Vec<QuantumCell<F>> = bytes
                .iter()
                .map(|&x| QuantumCell::Witness(Value::known(F::from(x as u64))))
                .collect_vec();
            self.assert_crt_int_byte_repr(
                ctx,
                &ecdsa_chip.range,
                crt_integer,
                &byte_cells,
                &powers_of_256_cells,
            )?;
            Ok(byte_cells)
        };

        // assert the assigned_msg_hash_le is the right decomposition of msg_hash
        // msg_hash is an overflowing integer with 3 limbs, of sizes 88, 88, and 80
        let assigned_msg_hash_le =
            assert_crt(ctx, sign_data.msg_hash.to_repr(), &assigned_data.msg_hash)?;

        // ================================================
        // pk cells
        // ================================================
        let (x, y) = sign_data.pk.into_coordinates();

        let pk_x_le = x
            .to_repr()
            .iter()
            .map(|&x| QuantumCell::Witness(Value::known(F::from_u128(x as u128))))
            .collect_vec();
        let pk_y_le = y
            //.to_bytes()
            .to_repr()
            .iter()
            .map(|&y| QuantumCell::Witness(Value::known(F::from_u128(y as u128))))
            .collect_vec();
        let pk_assigned = ecc_chip.load_private(ctx, (Value::known(x), Value::known(y)));

        self.assert_crt_int_byte_repr(
            ctx,
            &ecdsa_chip.range,
            &pk_assigned.x,
            &pk_x_le,
            &powers_of_256_cells,
        )?;
        self.assert_crt_int_byte_repr(
            ctx,
            &ecdsa_chip.range,
            &pk_assigned.y,
            &pk_y_le,
            &powers_of_256_cells,
        )?;

        let assigned_pk_le_selected = [pk_y_le, pk_x_le].concat();
        log::trace!("finished data decomposition");

        let r_cells = assert_crt(
            ctx,
            //sign_data.signature.0.to_bytes(),
            sign_data.signature.0.to_repr(),
            &assigned_data.integer_r,
        )?;
        let s_cells = assert_crt(
            ctx,
            //sign_data.signature.1.to_bytes(),
            sign_data.signature.1.to_repr(),
            &assigned_data.integer_s,
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

    // this helper support both secp256k1 and secp256r1
    #[allow(clippy::too_many_arguments)]
    fn assign_sig_verify_generic<
        Fp: PrimeField<Repr = [u8; 32]> + halo2_base::utils::ScalarField,
        Fq: PrimeField<Repr = [u8; 32]> + halo2_base::utils::ScalarField,
        Affine: CurveAffine<Base = Fp, ScalarExt = Fq> + CurveAffineExt,
    >(
        &self,
        ctx: &mut Context<F>,
        rlc_chip: &RangeConfig<F>,
        sign_data: &SignData<Fq, Affine>,
        sign_data_decomposed: &SignDataDecomposed<F>,
        challenges: &Challenges<Value<F>>,
        assigned_ecdsa: &AssignedECDSA<F, FpConfig<F, Fp>>,
    ) -> Result<([AssignedValue<F>; 3], AssignedSignatureVerify<F>), Error> {
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
            evm_challenge_powers,
        );

        log::trace!("pk hash rlc halo2ecc: {:?}", pk_hash_rlc.value());
        log::trace!("finished sign verify");
        let to_be_keccak_checked = [sign_data_decomposed.is_address_zero, pk_rlc, pk_hash_rlc];
        let assigned_sig_verif = AssignedSignatureVerify {
            address: sign_data_decomposed.address,
            msg_len: sign_data.msg.len(),
            msg_rlc: challenges
                .keccak_input()
                .map(|r| rlc::value(sign_data.msg.iter().rev(), r)),
            msg_hash_rlc,
            sig_is_valid: assigned_ecdsa.sig_is_valid,
            r_rlc,
            s_rlc,
            v: assigned_ecdsa.v,
        };
        Ok((to_be_keccak_checked, assigned_sig_verif))
    }

    /// Assign witness data to the sig circuit.
    pub(crate) fn assign(
        &self,
        config: &SigCircuitConfig<F>,
        layouter: &mut impl Layouter<F>,
        signatures_k1: &[SignData<Fq_K1, Secp256k1Affine>],
        signatures_r1: &[SignData<Fq_R1, Secp256r1Affine>],
        challenges: &Challenges<Value<F>>,
    ) -> Result<Vec<AssignedSignatureVerify<F>>, Error> {
        if signatures_k1.len() > self.max_verify_k1 {
            error!(
                "signatures_k1.len() = {} > max_verify_k1 = {}",
                signatures_k1.len(),
                self.max_verify_k1
            );
            return Err(Error::Synthesis);
        }

        if signatures_r1.len() > self.max_verify_r1 {
            error!(
                "signatures_r1.len() = {} > max_verify_r1 = {}",
                signatures_r1.len(),
                self.max_verify_r1
            );
            return Err(Error::Synthesis);
        }

        let mut first_pass = SKIP_FIRST_PASS;
        let ecdsa_k1_chip = &config.ecdsa_k1_config;
        let ecdsa_r1_chip = &config.ecdsa_r1_config;

        let assigned_sig_verifs = layouter.assign_region(
            || "ecdsa chip verification",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(vec![]);
                }

                // no need `new_context` for ecdsa_r1_chip ?.
                let mut ctx = ecdsa_k1_chip.new_context(region);

                // ================================================
                // step 1: assert the signature is valid in circuit
                // ================================================

                let assigned_ecdsas_k1 = signatures_k1
                    .iter()
                    .chain(std::iter::repeat(&SignData::default()))
                    .take(self.max_verify_k1)
                    .map(|sign_data| self.assign_ecdsa_generic(&mut ctx, ecdsa_k1_chip, sign_data))
                    .collect::<Result<Vec<AssignedECDSA<F, FpChipK1<F>>>, Error>>()?;

                let assigned_ecdsas_r1 = signatures_r1
                    .iter()
                    .chain(std::iter::repeat(
                        &SignData::<Fq_R1, Secp256r1Affine>::default(),
                    ))
                    .take(self.max_verify_r1)
                    .map(|sign_data| self.assign_ecdsa_generic(&mut ctx, ecdsa_r1_chip, sign_data))
                    .collect::<Result<Vec<AssignedECDSA<F, FpChipR1<F>>>, Error>>()?;

                // ================================================
                // step 2: decompose the keys and messages
                // ================================================

                let sign_data_k1_decomposed = signatures_k1
                    .iter()
                    .chain(std::iter::repeat(&SignData::default()))
                    .take(self.max_verify_k1)
                    .zip_eq(assigned_ecdsas_k1.iter())
                    .map(|(sign_data, assigned_ecdsa)| {
                        self.sign_data_decomposition_generic(
                            &mut ctx,
                            ecdsa_k1_chip,
                            sign_data,
                            assigned_ecdsa,
                        )
                    })
                    .collect::<Result<Vec<SignDataDecomposed<F>>, Error>>()?;

                let sign_data_r1_decomposed = signatures_r1
                    .iter()
                    .chain(std::iter::repeat(
                        &SignData::<Fq_R1, Secp256r1Affine>::default(),
                    ))
                    .take(self.max_verify_r1)
                    .zip_eq(assigned_ecdsas_r1.iter())
                    .map(|(sign_data, assigned_ecdsa)| {
                        self.sign_data_decomposition_generic(
                            &mut ctx,
                            ecdsa_r1_chip,
                            sign_data,
                            assigned_ecdsa,
                        )
                    })
                    .collect::<Result<Vec<SignDataDecomposed<F>>, Error>>()?;

                // IMPORTANT: Move to Phase2 before RLC
                log::info!("before proceeding to the next phase");

                #[cfg(not(feature = "onephase"))]
                {
                    // finalize the current lookup table before moving to next phase
                    // can only finalize one chip like ecdsa_k1_chip.
                    ecdsa_k1_chip.finalize(&mut ctx);
                    ctx.print_stats(&["ECDSA context"]);
                    ctx.next_phase();
                }

                // ================================================
                // step 3: compute RLC of keys and messages
                // ================================================

                let (mut assigned_keccak_values, mut assigned_sig_values): (
                    Vec<[AssignedValue<F>; 3]>,
                    Vec<AssignedSignatureVerify<F>>,
                ) = signatures_k1
                    .iter()
                    .chain(std::iter::repeat(&SignData::default()))
                    .take(self.max_verify_k1)
                    .zip_eq(assigned_ecdsas_k1.iter())
                    .zip_eq(sign_data_k1_decomposed.iter())
                    .map(|((sign_data, assigned_ecdsa), sign_data_decomp)| {
                        self.assign_sig_verify_generic(
                            &mut ctx,
                            &ecdsa_k1_chip.range,
                            sign_data,
                            sign_data_decomp,
                            challenges,
                            assigned_ecdsa,
                        )
                    })
                    .collect::<Result<
                        Vec<([AssignedValue<F>; 3], AssignedSignatureVerify<F>)>,
                        Error,
                    >>()?
                    .into_iter()
                    .unzip();

                let (assigned_keccak_values_r1, assigned_sig_values_r1): (
                    Vec<[AssignedValue<F>; 3]>,
                    Vec<AssignedSignatureVerify<F>>,
                ) = signatures_r1
                    .iter()
                    .chain(std::iter::repeat(&SignData::<Fq_R1,Secp256r1Affine>::default()))
                    .take(self.max_verify_r1)
                    .zip_eq(assigned_ecdsas_r1.iter())
                    .zip_eq(sign_data_r1_decomposed.iter())
                    .map(|((sign_data, assigned_ecdsa), sign_data_decomp)| {
                        self.assign_sig_verify_generic(
                            &mut ctx,
                            &ecdsa_r1_chip.range,
                            sign_data,
                            sign_data_decomp,
                            challenges,
                            assigned_ecdsa,
                        )
                    })
                    .collect::<Result<
                        Vec<([AssignedValue<F>; 3], AssignedSignatureVerify<F>)>,
                        Error,
                    >>()?
                    .into_iter()
                    .unzip();

                // append keccak & sig values of r1
                assigned_keccak_values.extend(assigned_keccak_values_r1);
                assigned_sig_values.extend(assigned_sig_values_r1);
                // ================================================
                // step 4: deferred keccak checks
                // ================================================

                for (i, [is_address_zero, pk_rlc, pk_hash_rlc]) in
                    assigned_keccak_values.iter().enumerate()
                {
                    let offset = i * 3;
                    self.enable_keccak_lookup(
                        config,
                        &mut ctx,
                        offset,
                        is_address_zero,
                        pk_rlc,
                        pk_hash_rlc,
                    )?;
                }

                // IMPORTANT: this assigns all constants to the fixed columns
                // IMPORTANT: this copies cells to the lookup advice column to perform range
                // check lookups
                // This is not optional.
                let lookup_cells = ecdsa_k1_chip.finalize(&mut ctx);

                log::info!("total number of lookup cells: {}", lookup_cells);

                ctx.print_stats(&["ECDSA context"]);
                Ok(assigned_sig_values)
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

                    assigned_sig_verif
                        .v
                        .copy_advice(&mut region, config.sig_table.sig_v, idx);

                    assigned_sig_verif.r_rlc.copy_advice(
                        &mut region,
                        config.sig_table.sig_r_rlc,
                        idx,
                    );

                    assigned_sig_verif.s_rlc.copy_advice(
                        &mut region,
                        config.sig_table.sig_s_rlc,
                        idx,
                    );

                    assigned_sig_verif.address.copy_advice(
                        &mut region,
                        config.sig_table.recovered_addr,
                        idx,
                    );

                    assigned_sig_verif.sig_is_valid.copy_advice(
                        &mut region,
                        config.sig_table.is_valid,
                        idx,
                    );

                    assigned_sig_verif.msg_hash_rlc.copy_advice(
                        &mut region,
                        config.sig_table.msg_hash_rlc,
                        idx,
                    );
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
    ) -> Result<(), Error> {
        // length of byte representation is 32
        assert_eq!(byte_repr.len(), 32);
        // need to support decomposition of up to 88 bits
        assert!(powers_of_256.len() >= 11);

        let flex_gate_chip = &range_chip.gate;

        // apply the overriding flag
        let limb1_value = crt_int.truncation.limbs[0];
        let limb2_value = crt_int.truncation.limbs[1];
        let limb3_value = crt_int.truncation.limbs[2];

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
            QuantumCell::Existing(limb1_value),
            QuantumCell::Existing(limb1_recover),
        );
        flex_gate_chip.assert_equal(
            ctx,
            QuantumCell::Existing(limb2_value),
            QuantumCell::Existing(limb2_recover),
        );
        flex_gate_chip.assert_equal(
            ctx,
            QuantumCell::Existing(limb3_value),
            QuantumCell::Existing(limb3_recover),
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
}
