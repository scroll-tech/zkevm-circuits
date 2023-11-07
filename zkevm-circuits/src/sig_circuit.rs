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
    evm_circuit::{
        util::{not, rlc},
        EvmCircuit,
    },
    keccak_circuit::KeccakCircuit,
    sig_circuit::ecdsa::ecdsa_verify_no_pubkey_check,
    table::{KeccakTable, SigTable},
    util::{Challenges, Expr, SubCircuit, SubCircuitConfig},
};
use eth_types::{
    self,
    sign_types::{pk_bytes_le, pk_bytes_swap_endianness, SignData},
    Field,
};
use halo2_base::{
    gates::{
        circuit::{
            builder::{BaseCircuitBuilder, RangeCircuitBuilder},
            BaseCircuitParams, BaseConfig,
        },
        flex_gate::{FlexGateConfig, FlexGateConfigParams},
        range::RangeConfig,
        GateChip, GateInstructions, RangeChip, RangeInstructions,
    },
    utils::{modulus, BigPrimeField},
    virtual_region::lookups::LookupAnyManager,
    AssignedValue, Context, QuantumCell, SKIP_FIRST_PASS,
};
use halo2_ecc::{
    bigint::{CRTInteger, ProperCrtUint},
    ecc::EccChip,
    fields::{
        fp::{FpChip, FpConfig},
        FieldChip,
    },
};
use snark_verifier::loader::halo2::IntegerInstructions;

mod ecdsa;
mod utils;
#[cfg(any(feature = "test", test, feature = "test-circuits"))]
pub(crate) use utils::*;

use halo2_proofs::{
    circuit::{AssignedCell, Cell, Layouter, Region, Value},
    halo2curves::secp256k1::{Fp, Fq, Secp256k1Affine},
    plonk::{Advice, Assigned, Circuit, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};

use ethers_core::utils::keccak256;
use itertools::Itertools;
use log::error;
use std::{borrow::BorrowMut, cell::RefCell, iter, marker::PhantomData};

/// Transmute data from halo2 lib to halo2 proof; and vice versa
struct TransmuteData<F: Field> {
    assigned_keccak_values: Vec<[AssignedValue<F>; 3]>,
    // assigned_keccak_cells: Vec<Vec<Cell>>,
    assigned_sig_values: Vec<AssignedSignatureVerify<F>>,
    // assigned_sig_values: Vec<AssignedSignatureVerify<F>>
}

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
    /// halo2-lib config
    pub range_config: BaseConfig<F>,
    /// halo2-lib config
    pub base_config: BaseConfig<F>,
    /// ECDSA parameters
    /// TODO: move to somewhere else
    num_limbs: usize,
    limb_bits: usize,
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
        let num_advice = vec![calc_required_advices(MAX_NUM_SIG), 1];

        let num_lookup_advice = vec![calc_required_lookup_advices(MAX_NUM_SIG), 1];

        #[cfg(feature = "onephase")]
        log::info!("configuring ECDSA chip with single phase");
        #[cfg(not(feature = "onephase"))]
        log::info!("configuring ECDSA chip with multiple phases");

        // halo2-ecc's range config
        // todo: move param to Cricuit::Param once SubCircuit trait supports Param
        let range_circuit_param = BaseCircuitParams {
            k: LOG_TOTAL_NUM_ROWS,
            num_advice_per_phase: num_advice,
            num_fixed: 2,
            num_lookup_advice_per_phase: num_lookup_advice,
            lookup_bits: Some(LOG_TOTAL_NUM_ROWS - 1),
            num_instance_columns: 0,
        };

        let range_circuit_config =
            BaseCircuitBuilder::configure_with_params(meta, range_circuit_param);
        let base_circuit_param = BaseCircuitParams {
            k: 10,
            num_advice_per_phase: vec![0,1],
            num_fixed: 1,
            num_lookup_advice_per_phase: vec![],
            lookup_bits: None,
            num_instance_columns: 0,
        };
        let base_circuit_config =
            BaseCircuitBuilder::configure_with_params(meta, base_circuit_param);

        // let range_config = RangeCircuitBuilder::configure_with_params(meta, base_circuit_param);

        // we need one phase 2 column to store RLC results
        #[cfg(feature = "onephase")]
        let rlc_column = meta.advice_column_in(halo2_proofs::plonk::FirstPhase);
        #[cfg(not(feature = "onephase"))]
        //
        let rlc_column = meta.advice_column_in(halo2_proofs::plonk::SecondPhase);
        // let rlc_column = meta.advice_column_in(halo2_proofs::plonk::FirstPhase);

        meta.enable_equality(rlc_column);

        meta.enable_equality(sig_table.recovered_addr);
        meta.enable_equality(sig_table.sig_r_rlc);
        meta.enable_equality(sig_table.sig_s_rlc);
        meta.enable_equality(sig_table.sig_v);
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
            range_config: range_circuit_config,
            base_config: base_circuit_config,
            limb_bits: 88,
            num_limbs: 3,
            keccak_table,
            sig_table,
            q_keccak,
            rlc_column,
        }
    }
}

// impl<F: Field> SigCircuitConfig<F> {
//     pub(crate) fn load_range(&self, mut layouter: impl Layouter<F>) -> Result<(), Error> {
//         self.ecdsa_config.range.load_lookup_table(layouter)
//     }
// }

/// Verify a message hash is signed by the public
/// key corresponding to an Ethereum Address.
#[derive(Clone, Debug, Default)]
pub struct SigCircuit<F: Field> {
    /// halo2-lib circuit builders
    pub phase_1_builder: RefCell<RangeCircuitBuilder<F>>,
    // /// halo2-lib circuit builders
    // pub phase_2_builder: RefCell<BaseCircuitBuilder<F>>,
    /// chip used for halo2-lib
    pub gate_chip: GateChip<F>,
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
        assert!(block.circuits_params.max_txs <= MAX_NUM_SIG);
        let phase_1_builder = RangeCircuitBuilder::new(false);
        // let phase_2_builder = BaseCircuitBuilder::new(false);
        SigCircuit {
            phase_1_builder: RefCell::new(phase_1_builder),
            // phase_2_builder: RefCell::new(phase_2_builder),
            gate_chip: GateChip::new(),
            max_verif: MAX_NUM_SIG,
            signatures: block.get_sign_data(true),
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
        // config.ecdsa_config.range.load_lookup_table(layouter)?;
        self.assign(config, layouter, &self.signatures, challenges)?;
        Ok(())
    }

    // Since sig circuit / halo2-lib use vertical cell assignment,
    // so the returned pair is consisted of same values
    fn min_num_rows_block(block: &crate::witness::Block<F>) -> (usize, usize) {
        let row_num = if block.circuits_params.max_vertical_circuit_rows == 0 {
            Self::min_num_rows()
        } else {
            block.circuits_params.max_vertical_circuit_rows
        };

        let ecdsa_verif_count = block
            .txs
            .iter()
            .filter(|tx| !tx.tx_type.is_l1_msg())
            .count()
            + block.precompile_events.get_ecrecover_events().len();
        // Reserve one ecdsa verification for padding tx such that the bad case in which some tx
        // calls MAX_NUM_SIG - 1 ecrecover precompile won't happen. If that case happens, the sig
        // circuit won't have more space for the padding tx's ECDSA verification. Then the
        // prover won't be able to produce any valid proof.
        let max_num_verif = MAX_NUM_SIG - 1;

        // Instead of showing actual minimum row usage,
        // halo2-lib based circuits use min_row_num to represent a percentage of total-used capacity
        // This functionality allows l2geth to decide if additional ops can be added.
        let min_row_num = (row_num / max_num_verif) * ecdsa_verif_count;

        (min_row_num, row_num)
    }
}

impl<F: Field> SigCircuit<F> {
    /// Return a new SigCircuit
    pub fn new(max_verif: usize) -> Self {
        let phase_1_builder = RangeCircuitBuilder::new(false);
        // let phase_2_builder = BaseCircuitBuilder::new(false);
        SigCircuit {
            phase_1_builder: RefCell::new(phase_1_builder),
            // phase_2_builder: RefCell::new(phase_2_builder),
            gate_chip: GateChip::default(),
            max_verif,
            signatures: Vec::new(),
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
        ecdsa_chip: &EccChip<F, FpChip<F, Fp>>,
        sign_data: &SignData,
    ) -> Result<AssignedECDSA<F, FpChip<F, Fp>>, Error> {
        let gate = ecdsa_chip.field_chip().gate();
        let base_chip = ecdsa_chip.field_chip;
        let scalar_chip =
            FpChip::<F, Fq>::new(base_chip.range, base_chip.limb_bits, base_chip.num_limbs);

        let zero = ctx.load_constant(F::zero());

        let SignData {
            signature,
            pk,
            msg: _,
            msg_hash,
        } = sign_data;
        let (sig_r, sig_s, v) = signature;

        // build ecc chip from Fp chip
        let pk_assigned = ecdsa_chip.load_private_unchecked(ctx, (pk.x, pk.y));
        let pk_is_valid = ecdsa_chip.is_on_curve_or_infinity::<Secp256k1Affine>(ctx, &pk_assigned);
        gate.assert_is_const(ctx, &pk_is_valid, &F::one());

        // build Fq chip from Fp chip
        // let fq_chip = FqChip::construct(ecdsa_chip.range.clone(), 88, 3, modulus::<Fq>());
        let integer_r = scalar_chip.load_private(ctx, *sig_r);
        let integer_s = scalar_chip.load_private(ctx, *sig_s);
        let msg_hash = scalar_chip.load_private(ctx, *msg_hash);

        // returns the verification result of ecdsa signature
        //
        // WARNING: this circuit does not enforce the returned value to be true
        // make sure the caller checks this result!
        let (sig_is_valid, pk_is_zero, y_coord) =
            ecdsa_verify_no_pubkey_check::<F, Fp, Fq, Secp256k1Affine>(
                &ecdsa_chip,
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

        let assigned_y_is_odd = ctx.load_witness(F::from(*v as u64));
        gate.assert_bit(ctx, assigned_y_is_odd);

        // the last 88 bits of y
        let assigned_y_limb = &y_coord.limbs()[0];
        let y_value = *assigned_y_limb.value();

        // y_tmp = (y_value - y_last_bit)/2
        let y_tmp = (y_value - F::from(*v as u64)) * F::TWO_INV;
        let assigned_y_tmp = ctx.load_witness(y_tmp);

        // y_tmp_double = (y_value - y_last_bit)
        let y_tmp_double = gate.mul(ctx, assigned_y_tmp, QuantumCell::Constant(F::from(2)));
        let y_rec = gate.add(ctx, y_tmp_double, assigned_y_is_odd);
        let y_is_ok = gate.is_equal(ctx, *assigned_y_limb, y_rec);

        // last step we want to constrain assigned_y_tmp is 87 bits
        let assigned_y_tmp = gate.select(ctx, zero, assigned_y_tmp, pk_is_zero);
        base_chip.range.range_check(ctx, assigned_y_tmp, 87);

        let pk_not_zero = gate.not(ctx, QuantumCell::Existing(pk_is_zero));
        let sig_is_valid = gate.and(ctx, sig_is_valid, y_is_ok);
        let sig_is_valid = gate.and(ctx, sig_is_valid, pk_not_zero);

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

    fn enable_keccak_lookup(
        &self,
        config: &SigCircuitConfig<F>,
        region: &mut Region<F>,
        offset: usize,
        is_address_zero: &AssignedValue<F>,
        pk_rlc: &AssignedValue<F>,
        pk_hash_rlc: &AssignedValue<F>,
    ) -> Result<[AssignedCell<F, F>; 3], Error> {
        log::trace!("keccak lookup");

        // Layout:
        // | q_keccak |        rlc      |
        // | -------- | --------------- |
        // |     1    | is_address_zero |
        // |          |    pk_rlc       |
        // |          |    pk_hash_rlc  |
        config.q_keccak.enable(region, offset)?;

        // is_address_zero
        let is_address_zero = region.assign_advice(
            || "is_address_zero",
            config.rlc_column,
            offset,
            || Value::known(*is_address_zero.value()),
        )?;

        // pk_rlc
        let pk_rlc = region.assign_advice(
            || "pk_rlc",
            config.rlc_column,
            offset + 1,
            || Value::known(*pk_rlc.value()),
        )?;

        // pk_hash_rlc
        let pk_hash_rlc = region.assign_advice(
            || "pk_hash_rlc",
            config.rlc_column,
            offset + 2,
            || Value::known(*pk_hash_rlc.value()),
        )?;

        log::trace!("finished keccak lookup");
        Ok([is_address_zero, pk_rlc, pk_hash_rlc])
    }

    /// Input the signature data,
    /// Output the cells for byte decomposition of the keys and messages
    fn sign_data_decomposition(
        &self,
        ctx: &mut Context<F>,
        ecc_chip: &EccChip<F, FpChip<F, Fp>>,
        sign_data: &SignData,
        assigned_data: &AssignedECDSA<F, FpChip<F, Fp>>,
    ) -> Result<SignDataDecomposed<F>, Error> {
        let flex_gate_chip = ecc_chip.field_chip.gate();
        let zero = ctx.load_constant(F::ZERO);

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
        let pk_hash = keccak256(pk_be).map(|byte| F::from(byte as u64));

        log::trace!("pk hash {:0x?}", pk_hash);
        let pk_hash_cells = pk_hash
            .iter()
            .map(|&x| QuantumCell::Witness(x))
            .rev()
            .collect_vec();

        // address is the random linear combination of the public key
        // it is fine to use a phase 1 gate here
        let address = flex_gate_chip.inner_product(
            ctx,
            powers_of_256_cells[..20].to_vec(),
            pk_hash_cells[..20].to_vec(),
        );
        let address = flex_gate_chip.select(ctx, zero, address, assigned_data.pk_is_zero);
        let is_address_zero = flex_gate_chip.is_equal(ctx, address, zero);
        log::trace!("address: {:?}", address.value());

        // ================================================
        // message hash cells
        // ================================================
        let assert_crt = |ctx: &mut Context<F>,
                          bytes: [u8; 32],
                          crt_integer: &ProperCrtUint<F>|
         -> Result<_, Error> {
            let byte_cells: Vec<QuantumCell<F>> = bytes
                .iter()
                .map(|&x| QuantumCell::Witness(F::from(x as u64)))
                .collect_vec();
            self.assert_crt_int_byte_repr(
                ctx,
                &flex_gate_chip,
                crt_integer,
                &byte_cells,
                &powers_of_256_cells,
            )?;
            Ok(byte_cells)
        };

        // assert the assigned_msg_hash_le is the right decomposition of msg_hash
        // msg_hash is an overflowing integer with 3 limbs, of sizes 88, 88, and 80
        let assigned_msg_hash_le =
            assert_crt(ctx, sign_data.msg_hash.to_bytes(), &assigned_data.msg_hash)?;

        // ================================================
        // pk cells
        // ================================================
        let pk_x_le = sign_data
            .pk
            .x
            .to_bytes()
            .iter()
            .map(|&x| QuantumCell::Witness(F::from_u128(x as u128)))
            .collect_vec();
        let pk_y_le = sign_data
            .pk
            .y
            .to_bytes()
            .iter()
            .map(|&y| QuantumCell::Witness(F::from_u128(y as u128)))
            .collect_vec();
        let pk_assigned =
            ecc_chip.load_private::<Secp256k1Affine>(ctx, (sign_data.pk.x, sign_data.pk.y));

        self.assert_crt_int_byte_repr(
            ctx,
            &flex_gate_chip,
            &pk_assigned.x,
            &pk_x_le,
            &powers_of_256_cells,
        )?;
        self.assert_crt_int_byte_repr(
            ctx,
            &flex_gate_chip,
            &pk_assigned.y,
            &pk_y_le,
            &powers_of_256_cells,
        )?;

        let assigned_pk_le_selected = [pk_y_le, pk_x_le].concat();
        log::trace!("finished data decomposition");

        let r_cells = assert_crt(
            ctx,
            sign_data.signature.0.to_bytes(),
            &assigned_data.integer_r,
        )?;
        let s_cells = assert_crt(
            ctx,
            sign_data.signature.1.to_bytes(),
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

    #[allow(clippy::too_many_arguments)]
    fn assign_sig_verify(
        &self,
        ctx: &mut Context<F>,
        flex_gate_chip: &GateChip<F>,
        sign_data: &SignData,
        sign_data_decomposed: &SignDataDecomposed<F>,
        challenges: &Challenges<Value<F>>,
        assigned_ecdsa: &AssignedECDSA<F, FpChip<F, Fp>>,
    ) -> Result<([AssignedValue<F>; 3], AssignedSignatureVerify<F>), Error> {
        // ================================================
        // step 0. powers of aux parameters
        // ================================================
        let evm_challenge_powers = {
            let mut evm_word = F::default();
            challenges.evm_word().map(|x| evm_word = x);
            // let start_point = F::from(evm_word != F::ZERO);
            // iter::successors(Some(start_point), |&coeff| Some(evm_word * coeff))
            iter::successors(Some(F::one()), |&coeff| Some(evm_word * coeff))
                .take(32)
                .map(|x| QuantumCell::Witness(x))
                .collect_vec()
        };

        log::trace!("evm challenge: {:?} ", challenges.evm_word());

        let keccak_challenge_powers = {
            let mut keccak_input = F::default();
            challenges.keccak_input().map(|x| keccak_input = x);
            // let start_point = F::from(keccak_input != F::ZERO);
            // iter::successors(Some(start_point), |coeff| Some(keccak_input * coeff))
            iter::successors(Some(F::one()), |coeff| Some(keccak_input * coeff))
                .take(64)
                .map(|x| QuantumCell::Witness(x))
                .collect_vec()
        };

        // ================================================
        // step 1 random linear combination of message hash
        // ================================================
        // Ref. spec SignVerifyChip 3. Verify that the signed message in the ecdsa_chip
        // with RLC encoding corresponds to msg_hash_rlc
        let msg_hash_rlc = flex_gate_chip.inner_product(
            ctx,
            sign_data_decomposed
                .msg_hash_cells
                .iter()
                .take(32)
                .cloned()
                .collect_vec(),
            evm_challenge_powers.clone(),
        );

        println!("assigned msg hash rlc: {:?}", msg_hash_rlc.value());

        // ================================================
        // step 2 random linear combination of pk
        // ================================================
        let pk_rlc = flex_gate_chip.inner_product(
            ctx,
            sign_data_decomposed.pk_cells.clone(),
            keccak_challenge_powers,
        );
        println!("pk rlc: {:?}", pk_rlc.value());

        // ================================================
        // step 3 random linear combination of pk_hash
        // ================================================
        let pk_hash_rlc = flex_gate_chip.inner_product(
            ctx,
            sign_data_decomposed.pk_hash_cells.clone(),
            evm_challenge_powers.clone(),
        );

        // step 4: r,s rlc
        let r_rlc = flex_gate_chip.inner_product(
            ctx,
            sign_data_decomposed.r_cells.clone(),
            evm_challenge_powers.clone(),
        );
        let s_rlc = flex_gate_chip.inner_product(
            ctx,
            sign_data_decomposed.s_cells.clone(),
            evm_challenge_powers,
        );

        println!("pk hash rlc halo2ecc: {:?}", pk_hash_rlc.value());
        log::trace!("finished sign verify");
        let to_be_keccak_checked = [sign_data_decomposed.is_address_zero, pk_rlc, pk_hash_rlc];
        println!(
            "to be keccaked: {:?}",
            sign_data_decomposed.is_address_zero.value()
        );
        println!("to be keccaked: {:?}", pk_rlc.value());
        println!("to be keccaked: {:?}", pk_hash_rlc.value());
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

    fn extract_transmute_data(
        &self,
        config: &SigCircuitConfig<F>,
        layouter: &mut impl Layouter<F>,
        signatures: &[SignData],
        challenges: &Challenges<Value<F>>,
    ) -> Result<TransmuteData<F>, Error> {
        let (assigned_ecdsas, sign_data_decomposed) = {
            let mut builder = self.phase_1_builder.borrow_mut();
            let lookup_manager = builder.lookup_manager().clone();
            let range_chip = RangeChip::new(LOG_TOTAL_NUM_ROWS - 1, lookup_manager);
            let fp_chip = FpChip::<F, Fp>::new(&range_chip, 88, 3);
            let ecc_chip = EccChip::new(&fp_chip);

            let mut ctx = builder.main(0);

            // ================================================
            // step 1: assert the signature is valid in circuit
            // ================================================

            let assigned_ecdsas = signatures
                .iter()
                .chain(std::iter::repeat(&SignData::default()))
                .take(self.max_verif)
                .map(|sign_data| self.assign_ecdsa(&mut ctx, &ecc_chip, sign_data))
                .collect::<Result<Vec<AssignedECDSA<F, FpChip<F, Fp>>>, Error>>()?;

            // ================================================
            // step 2: decompose the keys and messages
            // ================================================
            let sign_data_decomposed = signatures
                .iter()
                .chain(std::iter::repeat(&SignData::default()))
                .take(self.max_verif)
                .zip_eq(assigned_ecdsas.iter())
                .map(|(sign_data, assigned_ecdsa)| {
                    self.sign_data_decomposition(&mut ctx, &ecc_chip, sign_data, assigned_ecdsa)
                })
                .collect::<Result<Vec<SignDataDecomposed<F>>, Error>>()?;

            // builder.synthesize_ref_layouter(config.range_config.clone(), layouter)?;
            // builder.clear();
            (assigned_ecdsas, sign_data_decomposed)
        };

        // ================================================
        // step 3: compute RLC of keys and messages
        // ================================================
        println!("proceed to second phase");
        let (
            assigned_keccak_values,
            // assigned_keccak_cells,
            assigned_sig_values,
        ) = {
            // let lookup_manager = builder.lookup_manager().clone();
            // let range_chip = RangeChip::new(LOG_TOTAL_NUM_ROWS - 1, lookup_manager);
            // let fp_chip = FpChip::<F, Fp>::new(&range_chip, 88, 3);
            // let mut ctx = builder.main(1);

            // let mut builder = self.phase_2_builder.borrow_mut();
            let mut builder = self.phase_1_builder.borrow_mut();
            let gate_chip = GateChip::new();

            let mut ctx = builder.main(0);
            let (assigned_keccak_values, assigned_sig_values): (
                Vec<[AssignedValue<F>; 3]>,
                Vec<AssignedSignatureVerify<F>>,
            ) = signatures
                .iter()
                .chain(std::iter::repeat(&SignData::default()))
                .take(self.max_verif)
                .zip_eq(assigned_ecdsas.iter())
                .zip_eq(sign_data_decomposed.iter())
                .map(|((sign_data, assigned_ecdsa), sign_data_decomp)| {
                    self.assign_sig_verify(
                        &mut ctx,
                        &gate_chip,
                        sign_data,
                        sign_data_decomp,
                        challenges,
                        assigned_ecdsa,
                    )
                })
                .collect::<Result<Vec<([AssignedValue<F>; 3], AssignedSignatureVerify<F>)>, Error>>(
                )?
                .into_iter()
                .unzip();


                // println!("start synthesize1");
        // builder.synthesize_ref_layouter(config.range_config.clone(), layouter)?;
        // builder.clear();
            (
                assigned_keccak_values,
                // assigned_keccak_cells,
                assigned_sig_values,
            )
        };
        
        // ================================================
        // finalize the virtual cells and get their indexes
        // ================================================
        // builder.synthesize_ref_layouter(config.range_config.clone(), layouter)?;

        // let copy_manager = builder.core().copy_manager.lock().unwrap();
        // let hash_map = &copy_manager.assigned_advices;

        // println!("hash map size: {:?}", hash_map.len());


 // TODO: is this correct?
        layouter.assign_region(
            || "expose sig table",
            |mut region| {
                // step 5: export as a lookup table
                for (idx, assigned_sig_verif) in assigned_sig_values.iter().enumerate() {
                    region.assign_fixed(
                        || "assign sig_table selector",
                        config.sig_table.q_enable,
                        idx,
                        || Value::known(F::one()),
                    )?;

                    // assigned_sig_verif
                    //     .v
                    //     .copy_advice(&mut region, config.sig_table.sig_v, idx);

                    // assigned_sig_verif.r_rlc.copy_advice(
                    //     &mut region,
                    //     config.sig_table.sig_r_rlc,
                    //     idx,
                    // );

                    // assigned_sig_verif.s_rlc.copy_advice(
                    //     &mut region,
                    //     config.sig_table.sig_s_rlc,
                    //     idx,
                    // );

                    // assigned_sig_verif.address.copy_advice(
                    //     &mut region,
                    //     config.sig_table.recovered_addr,
                    //     idx,
                    // );

                    // assigned_sig_verif.sig_is_valid.copy_advice(
                    //     &mut region,
                    //     config.sig_table.is_valid,
                    //     idx,
                    // );

                    // assigned_sig_verif.msg_hash_rlc.copy_advice(
                    //     &mut region,
                    //     config.sig_table.msg_hash_rlc,
                    //     idx,
                    // );
                }
                Ok(())
            },
        )?;
        // todo!()

        // let assigned_keccak_cells = assigned_keccak_values
        //     .iter()
        //     .map(|array| {
        //         array
        //             .iter()
        //             .map(|elem| {
        //                 println!("{:?}", elem.value);
        //                 *hash_map.get(&elem.cell.unwrap()).unwrap()
        //             })
        //             .collect::<Vec<_>>()
        //     })
        //     .collect::<Vec<_>>();

        // drop(copy_manager);
        // builder.clear();

        Ok(TransmuteData {
            assigned_keccak_values,
            // assigned_keccak_cells,
            assigned_sig_values,
            // assigned_sig_values,
        })
    }

    fn equality_constraints(
        &self,
        config: &SigCircuitConfig<F>,
        layouter: &mut impl Layouter<F>,
        data: &TransmuteData<F>,
        cells: &[[AssignedCell<F, F>; 3]],
    ) -> Result<(), Error> {
        // let mut builder = self.phase_2_builder.borrow_mut();
        let mut builder = self.phase_1_builder.borrow_mut();
        let mut copy_manager_locked = builder.core().copy_manager.lock().unwrap();

        let mut t = vec![];
        for a in cells.iter() {
            let mut f = vec![];
            for b in a.iter() {
                let mut value = F::default();
                b.value().map(|f| value = *f);
                f.push(AssignedValue {
                    value: Assigned::Trivial(value),
                    cell: Some(copy_manager_locked.load_external_cell(b.cell())),
                });
            }
            t.push(f);
        }

        drop(copy_manager_locked);

        let ctx = builder.main(0);

        for (a, b) in t.iter().zip(data.assigned_keccak_values.iter()) {
            for (aa, bb) in a.iter().zip(b.iter()) {
                println!("a {:?}", aa.value);
                println!("b {:?}", bb.value);
                ctx.constrain_equal(aa, bb);
            }
        }
        // println!("start synthesize");
        // builder.synthesize_ref_layouter(config.range_config.clone(), layouter)?;
        // builder.clear();

        // println!("end synthesize");
        Ok(())
    }

    /// Assign witness data to the sig circuit.
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

        let transmute_data =
            self.extract_transmute_data(config, layouter, signatures, challenges)?;

        // ================================================
        // step 4: deferred keccak checks
        // ================================================

        let mut first_pass = halo2_base::SKIP_FIRST_PASS;

        let deferred_keccak_cells = layouter.assign_region(
            || "deferred keccak checks",
            |mut region| {
                // if first_pass {
                //     first_pass = false;
                //     return Ok(vec![]);
                // }

                let mut res = vec![];
                for (i, [is_address_zero, pk_rlc, pk_hash_rlc]) in
                    transmute_data.assigned_keccak_values.iter().enumerate()
                {
                    let offset = i * 3;
                    let cells = self.enable_keccak_lookup(
                        config,
                        &mut region,
                        offset,
                        is_address_zero,
                        pk_rlc,
                        pk_hash_rlc,
                    )?;
                    res.push(cells);
                }
                Ok(res)
            },
        )?;

        self.equality_constraints(config, layouter, &transmute_data, &deferred_keccak_cells)?;


        println!("start final assignment");
        let mut builder = self.phase_1_builder.borrow_mut();
        builder.synthesize_ref_layouter(config.range_config.clone(), layouter)?;
        builder.clear();
        println!("finished");


        // ========================================
        // ========================================
        // ========================================
        // ========================================
        // ========================================

        // let assigned_sig_verifs = layouter.assign_region(
        //     || "ecdsa chip verification",
        //     |region| {
        //         if first_pass {
        //             first_pass = false;
        //             return Ok(vec![]);
        //         }

        //         // let chip = s
        //         let mut ctx = self.builder.main(0);
        //         // let mut ctx = self.range_chip .new_context(region);

        //         // ================================================
        //         // step 1: assert the signature is valid in circuit
        //         // ================================================
        //         let assigned_ecdsas = signatures
        //             .iter()
        //             .chain(std::iter::repeat(&SignData::default()))
        //             .take(self.max_verif)
        //             .map(|sign_data| self.assign_ecdsa(&mut ctx, &ecc_chip, sign_data))
        //             .collect::<Result<Vec<AssignedECDSA<F, FpChip<F, Fp>>>, Error>>()?;

        //         // ================================================
        //         // step 2: decompose the keys and messages
        //         // ================================================
        //         let sign_data_decomposed = signatures
        //             .iter()
        //             .chain(std::iter::repeat(&SignData::default()))
        //             .take(self.max_verif)
        //             .zip_eq(assigned_ecdsas.iter())
        //             .map(|(sign_data, assigned_ecdsa)| {
        //                 self.sign_data_decomposition(&mut ctx, &ecc_chip, sign_data,
        // assigned_ecdsa)             })
        //             .collect::<Result<Vec<SignDataDecomposed<F>>, Error>>()?;

        //         // IMPORTANT: Move to Phase2 before RLC
        //         log::info!("before proceeding to the next phase");

        //         // #[cfg(not(feature = "onephase"))]
        //         // {
        //         //     // finalize the current lookup table before moving to next phase
        //         //     ecdsa_chip.finalize(&mut ctx);
        //         //     ctx.print_stats(&["ECDSA context"]);
        //         //     ctx.next_phase();
        //         // }

        //         // ================================================
        //         // step 3: compute RLC of keys and messages
        //         // ================================================
        //         let (assigned_keccak_values, assigned_sig_values): (
        //             Vec<[AssignedValue<F>; 3]>,
        //             Vec<AssignedSignatureVerify<F>>,
        //         ) = signatures
        //             .iter()
        //             .chain(std::iter::repeat(&SignData::default()))
        //             .take(self.max_verif)
        //             .zip_eq(assigned_ecdsas.iter())
        //             .zip_eq(sign_data_decomposed.iter())
        //             .map(|((sign_data, assigned_ecdsa), sign_data_decomp)| {
        //                 self.assign_sig_verify(
        //                     &mut ctx,
        //                     &ecc_chip.field_chip.gate(),
        //                     sign_data,
        //                     sign_data_decomp,
        //                     challenges,
        //                     assigned_ecdsa,
        //                 )
        //             })
        //             .collect::<Result<
        //                 Vec<([AssignedValue<F>; 3], AssignedSignatureVerify<F>)>,
        //                 Error,
        //             >>()?
        //             .into_iter()
        //             .unzip();

        //         // ================================================
        //         // step 4: deferred keccak checks
        //         // ================================================
        //         // for (i, [is_address_zero, pk_rlc, pk_hash_rlc]) in
        //         //     assigned_keccak_values.iter().enumerate()
        //         // {
        //         //     let offset = i * 3;
        //         //     self.enable_keccak_lookup(
        //         //         config,
        //         //         &mut ctx,
        //         //         offset,
        //         //         is_address_zero,
        //         //         pk_rlc,
        //         //         pk_hash_rlc,
        //         //     )?;
        //         // }

        //         // // IMPORTANT: this assigns all constants to the fixed columns
        //         // // IMPORTANT: this copies cells to the lookup advice column to perform range
        //         // // check lookups
        //         // // This is not optional.
        //         // let lookup_cells = ecdsa_chip.finalize(&mut ctx);
        //         // log::info!("total number of lookup cells: {}", lookup_cells);

        //         // ctx.print_stats(&["ECDSA context"]);
        //         Ok(assigned_sig_values)
        //     },
        // )?;

        // // TODO: is this correct?
        // layouter.assign_region(
        //     || "expose sig table",
        //     |mut region| {
        //         // step 5: export as a lookup table
        //         for (idx, assigned_sig_verif) in assigned_sig_values.iter().enumerate() {
        //             region.assign_fixed(
        //                 || "assign sig_table selector",
        //                 config.sig_table.q_enable,
        //                 idx,
        //                 || Value::known(F::one()),
        //             )?;

        //             // assigned_sig_verif
        //             //     .v
        //             //     .copy_advice(&mut region, config.sig_table.sig_v, idx);

        //             // assigned_sig_verif.r_rlc.copy_advice(
        //             //     &mut region,
        //             //     config.sig_table.sig_r_rlc,
        //             //     idx,
        //             // );

        //             // assigned_sig_verif.s_rlc.copy_advice(
        //             //     &mut region,
        //             //     config.sig_table.sig_s_rlc,
        //             //     idx,
        //             // );

        //             // assigned_sig_verif.address.copy_advice(
        //             //     &mut region,
        //             //     config.sig_table.recovered_addr,
        //             //     idx,
        //             // );

        //             // assigned_sig_verif.sig_is_valid.copy_advice(
        //             //     &mut region,
        //             //     config.sig_table.is_valid,
        //             //     idx,
        //             // );

        //             // assigned_sig_verif.msg_hash_rlc.copy_advice(
        //             //     &mut region,
        //             //     config.sig_table.msg_hash_rlc,
        //             //     idx,
        //             // );
        //         }
        //         Ok(())
        //     },
        // )?;
        // todo!()
        Ok(vec![])
        // Ok(transmute_data.assigned_sig_values)
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
        flex_gate_chip: &GateChip<F>,
        crt_int: &ProperCrtUint<F>,
        byte_repr: &[QuantumCell<F>],
        powers_of_256: &[QuantumCell<F>],
    ) -> Result<(), Error> {
        // length of byte representation is 32
        assert_eq!(byte_repr.len(), 32);
        // need to support decomposition of up to 88 bits
        assert!(powers_of_256.len() >= 11);

        // apply the overriding flag
        let limbs = crt_int.limbs();
        let limb1_value = limbs[0];
        let limb2_value = limbs[1];
        let limb3_value = limbs[2];

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
        ctx.constrain_equal(&limb1_value, &limb1_recover);
        ctx.constrain_equal(&limb2_value, &limb2_recover);
        ctx.constrain_equal(&limb3_value, &limb3_recover);

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
