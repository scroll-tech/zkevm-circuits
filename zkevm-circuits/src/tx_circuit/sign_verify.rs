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

use crate::{
    evm_circuit::util::{not, rlc},
    table::KeccakTable,
    util::{Challenges, Expr},
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
    ecc::{ecdsa::ecdsa_verify_no_pubkey_check, EcPoint, EccChip},
    fields::{
        fp::{FpConfig, FpStrategy},
        FieldChip,
    },
};
#[cfg(feature = "onephase")]
use halo2_proofs::plonk::FirstPhase;
#[cfg(not(feature = "onephase"))]
use halo2_proofs::plonk::SecondPhase;
use halo2_proofs::{
    circuit::{Cell, Layouter, Value},
    halo2curves::secp256k1::{Fp, Fq, Secp256k1Affine},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector},
    poly::Rotation,
};

use itertools::Itertools;
use keccak256::plain::Keccak;
use log::error;
use std::{iter, marker::PhantomData};

// Hard coded parameters.
// FIXME: allow for a configurable param.
const MAX_NUM_SIG: usize = 32;
// Each ecdsa signature requires 534042 cells
// We set CELLS_PER_SIG = 535000 to allows for a few buffer
const CELLS_PER_SIG: usize = 535000;
// Total number of rows allocated for ecdsa chip
const TOTAL_NUM_ROWS: usize = 19;

fn calc_required_advices(num_verif: usize) -> usize {
    let mut num_adv = 1;
    let total_cells = num_verif * CELLS_PER_SIG;
    while num_adv < 150 {
        if num_adv << TOTAL_NUM_ROWS > total_cells {
            log::info!(
                "ecdsa chip uses {} advice columns for {} signatures",
                num_adv,
                num_verif
            );
            return num_adv;
        }
        num_adv += 1;
    }
    panic!(
        "the required advice columns exceeds 100 for {} signatures",
        num_verif
    );
}

/// Chip to handle overflow integers of ECDSA::Fq, the scalar field
type FqChip<F> = FpConfig<F, Fq>;
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
        // the cells are allocated vertically, i.e., given a TOTAL_NUM_ROWS * NUM_ADVICE
        // matrix, the allocator will try to use all the cells in the first column, then
        // the second column, etc.
        if num_verif * CELLS_PER_SIG > calc_required_advices(num_verif) << TOTAL_NUM_ROWS {
            log::error!(
                "ecdsa chip not enough rows. rows: {}, advice {}, num of sigs {}, cells per sig {}",
                TOTAL_NUM_ROWS,
                calc_required_advices(num_verif),
                num_verif,
                CELLS_PER_SIG
            )
        } else {
            log::info!(
                "ecdsa chip: rows: {}, advice {}, num of sigs {}, cells per sig {}",
                TOTAL_NUM_ROWS,
                calc_required_advices(num_verif),
                num_verif,
                CELLS_PER_SIG
            )
        }

        TOTAL_NUM_ROWS
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
    /// ECDSA
    ecdsa_config: FpChip<F>,
    /// A fixed column to store F::one
    // FIXME: it is pretty wasteful to allocate a new fixed column just
    // to store a constant value F::one.
    fixed_column: Column<Fixed>,
    /// An advice column to store RLC witnesses
    rlc_column: Column<Advice>,
    /// selector for keccak lookup table
    q_keccak: Selector,
    keccak_table: KeccakTable,
}

impl<F: Field> SignVerifyConfig<F> {
    pub(crate) fn new(meta: &mut ConstraintSystem<F>, keccak_table: KeccakTable) -> Self {
        #[cfg(feature = "onephase")]
        let num_advice = [calc_required_advices(MAX_NUM_SIG)];
        #[cfg(not(feature = "onephase"))]
        // need an additional phase 2 column/basic gate to hold the witnesses during RLC
        // computations
        let num_advice = [calc_required_advices(MAX_NUM_SIG), 1];

        #[cfg(feature = "onephase")]
        log::info!("configuring ECDSA chip with single phase");
        #[cfg(not(feature = "onephase"))]
        log::info!("configuring ECDSA chip with multiple phases");

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
            TOTAL_NUM_ROWS, // maximum k of the chip
        );

        // we are not really using this instance column
        let instance = meta.instance_column();
        meta.enable_equality(instance);
        // we will need one fixed column to check if ecdsa is valid
        let fixed_column = meta.fixed_column();
        meta.enable_equality(fixed_column);
        // we need one phase 2 column to store RLC results
        #[cfg(feature = "onephase")]
        let rlc_column = meta.advice_column_in(FirstPhase);
        #[cfg(not(feature = "onephase"))]
        let rlc_column = meta.advice_column_in(SecondPhase);
        meta.enable_equality(rlc_column);

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
            q_keccak,
            fixed_column,
            rlc_column,
        }
    }
}

impl<F: Field> SignVerifyConfig<F> {
    pub(crate) fn load_range(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        self.ecdsa_config.range.load_lookup_table(layouter)
    }
}

pub(crate) struct AssignedECDSA<'v, F: Field, FC: FieldChip<F>> {
    pk: EcPoint<F, FC::FieldPoint<'v>>,
    msg_hash: CRTInteger<'v, F>,
    sig_is_valid: AssignedValue<'v, F>,
}

/// Temp struct to hold the intermediate data; removing life timer.
// Issue with life timer:
//
// Suppose we have two piece of codes, that request different regions/contexts from the layouter.
// The first piece of the code will return an `assigned_cell` that is to be used by the second code
// piece. With halo2 we can safely pass this `assigned_cell` around. They are bounded by a life
// timer `'v` which is when the field element is created.
//
// Now in halo2-lib, there is an additional life timer which says an `assigned_cell` cannot outlive
// the `region` for which this cell is created. (is this understanding correct?)
// That means the output cells of the first region cannot be passed to the second region.
//
// To temporary resolve this issue, we create a temp struct without life timer.
// This works with halo2-lib/pse but not halo2-lib/axiom.
// We do not support halo2-lib/axiom.
//
// NOTE: this is a temp issue with halo2-lib v0.2.2.
// with halo2-lib v0.3.0 the timers are already removed.
// So we don't need this temp fix once we sync with halo2-lib audited version.
#[derive(Debug, Clone)]
pub(crate) struct AssignedValueNoTimer<F: Field> {
    pub cell: Cell,
    pub value: Value<F>,
    pub row_offset: usize,
    pub context_id: usize,
}

impl<'v, F: Field> From<AssignedValue<'v, F>> for AssignedValueNoTimer<F> {
    fn from(input: AssignedValue<'v, F>) -> Self {
        Self {
            cell: input.cell(),
            value: input.value,
            row_offset: input.row_offset,
            context_id: input.context_id,
        }
    }
}

impl<'v, F: Field> From<AssignedValueNoTimer<F>> for AssignedValue<'v, F> {
    fn from(input: AssignedValueNoTimer<F>) -> Self {
        Self {
            cell: input.cell,
            value: input.value,
            row_offset: input.row_offset,
            _marker: PhantomData::default(),
            context_id: input.context_id,
        }
    }
}

impl<'v, F: Field> From<&AssignedValueNoTimer<F>> for AssignedValue<'v, F> {
    fn from(input: &AssignedValueNoTimer<F>) -> Self {
        Self {
            cell: input.cell,
            value: input.value,
            row_offset: input.row_offset,
            _marker: PhantomData::default(),
            context_id: input.context_id,
        }
    }
}

#[derive(Debug)]
pub(crate) struct AssignedSignatureVerify<F: Field> {
    pub(crate) address: AssignedValueNoTimer<F>,
    pub(crate) msg_len: usize,
    pub(crate) msg_rlc: Value<F>,
    pub(crate) msg_hash_rlc: AssignedValueNoTimer<F>,
    pub(crate) sig_is_valid: AssignedValueNoTimer<F>,
}

struct SignDataDecomposed<'a: 'v, 'v, F: Field> {
    pk_hash_cells: Vec<QuantumCell<'a, 'v, F>>,
    msg_hash_cells: Vec<QuantumCell<'a, 'v, F>>,
    pk_cells: Vec<QuantumCell<'a, 'v, F>>,
    address: AssignedValue<'v, F>,
    is_address_zero: AssignedValue<'v, F>,
}

impl<F: Field> SignVerifyChip<F> {
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
        let (sig_r, sig_s) = signature;

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
            sig_is_valid: ecdsa_is_valid,
        })
    }

    fn enable_keccak_lookup(
        &self,
        config: &SignVerifyConfig<F>,
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
        let pk_hash = (!padding)
            .then(|| {
                let mut keccak = Keccak::default();
                keccak.update(&pk_be);
                let hash: [_; 32] = keccak.digest().try_into().expect("vec to array of size 32");
                hash
            })
            .unwrap_or_default()
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
            FqChip::<F>::fe_to_witness(&Value::known(sign_data.msg_hash)),
        );

        self.assert_crt_int_byte_repr(
            ctx,
            &ecdsa_chip.range,
            &assigned_msg_hash,
            &assigned_msg_hash_le,
            &powers_of_256_cells,
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
        Ok(SignDataDecomposed {
            pk_hash_cells,
            msg_hash_cells: assigned_msg_hash_le,
            pk_cells: assigned_pk_le_selected,
            address,
            is_address_zero,
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

        log::trace!("pk hash rlc halo2ecc: {:?}", pk_hash_rlc.value());
        log::trace!("finished sign verify");
        Ok((
            [
                sign_data_decomposed.is_address_zero.clone(),
                pk_rlc,
                pk_hash_rlc,
            ],
            AssignedSignatureVerify {
                address: sign_data_decomposed.address.clone().into(),
                msg_len: sign_data.msg.len(),
                msg_rlc: challenges
                    .keccak_input()
                    .map(|r| rlc::value(sign_data.msg.iter().rev(), r)),
                msg_hash_rlc: msg_hash_rlc.into(),
                sig_is_valid: sig_is_valid.clone().into(),
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
                // step 1: assert the signature is valid in circuit
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
                // step 2: decompose the keys and messages
                // ================================================
                let mut sign_data_decomposed_vec = Vec::new();
                for i in 0..assigned_ecdsas.len() {
                    let sign_data = signatures.get(i); // None when padding (enabled when address == 0)
                    let sign_data_decomposed =
                        self.sign_data_decomposition(&mut ctx, ecdsa_chip, sign_data)?;
                    sign_data_decomposed_vec.push(sign_data_decomposed);
                }

                // IMPORTANT: Move to Phase2 before RLC
                log::info!("before proceeding to the next phase");
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
                let mut assigned_sig_verifs = Vec::new();
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
                log::info!("total number of lookup cells: {}", lookup_cells);

                ctx.print_stats(&["Range"]);
                Ok(assigned_sig_verifs)
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

    pub(crate) fn assert_sig_is_valid(
        &self,
        config: &SignVerifyConfig<F>,
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
}

pub(crate) fn pub_key_hash_to_address<F: Field>(pk_hash: &[u8]) -> F {
    pk_hash[32 - 20..]
        .iter()
        .fold(F::zero(), |acc, b| acc * F::from(256) + F::from(*b as u64))
}

#[cfg(test)]
mod sign_verify_tests {
    use super::*;

    #[cfg(not(feature = "onephase"))]
    use crate::util::Challenges;
    #[cfg(feature = "onephase")]
    use crate::util::MockChallenges as Challenges;

    use bus_mapping::circuit_input_builder::keccak_inputs_sign_verify;
    use eth_types::sign_types::sign;
    use halo2_proofs::{
        arithmetic::Field as HaloField,
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        halo2curves::{bn256::Fr, group::Curve, secp256k1},
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
            let challenges = config.challenges.values(&layouter);
            config.sign_verify.load_range(&mut layouter)?;
            let assigned_sig_verifs = self.sign_verify.assign(
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
            self.sign_verify.assert_sig_is_valid(
                &config.sign_verify,
                &mut layouter,
                assigned_sig_verifs.as_slice(),
            )?;

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
        let mut rng = XorShiftRng::seed_from_u64(1);
        let max_sigs = [4];
        for max_sig in max_sigs.iter() {
            log::info!("testing for {} signatures", max_sig);
            let mut signatures = Vec::new();
            for _ in 0..*max_sig {
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

            let k = TOTAL_NUM_ROWS as u32;
            run::<Fr>(k, *max_sig, signatures);

            log::info!("end of testing for {} signatures", max_sig);
        }
    }
}
