//! Circuit to verify multiple ECDSA secp256k1 signatures.

// Naming notes:
// - *_be: Big-Endian bytes
// - *_le: Little-Endian bytes

use crate::{
    evm_circuit::util::{not, rlc},
    table::KeccakTable,
    util::{Challenges, Expr},
};
use ecc::{maingate, EccConfig, GeneralEccChip};
use ecdsa::ecdsa::{AssignedEcdsaSig, AssignedPublicKey, EcdsaChip};
use eth_types::sign_types::{pk_bytes_le, pk_bytes_swap_endianness, SignData};
use eth_types::{self, Field};
use halo2_proofs::{
    arithmetic::{CurveAffine, FieldExt},
    circuit::{AssignedCell, Cell, Layouter, Value},
    halo2curves::secp256k1::Secp256k1Affine,
    halo2curves::{
        group::{Curve, Group},
        secp256k1,
    },
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector},
    poly::Rotation,
};
use integer::{AssignedInteger, IntegerChip, IntegerConfig, IntegerInstructions, Range};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use itertools::Itertools;
use keccak256::plain::Keccak;
use log::error;
use maingate::{
    AssignedValue, MainGate, MainGateConfig, MainGateInstructions, RangeChip, RangeConfig,
    RangeInstructions, RegionCtx,
};
use num::Integer;
use std::{iter, marker::PhantomData};

/// Auxiliary Gadget to verify a that a message hash is signed by the public
/// key corresponding to an Ethereum Address.
#[derive(Clone, Debug)]
pub struct SignVerifyChip<F: Field> {
    /// Aux generator for EccChip
    pub aux_generator: Secp256k1Affine,
    /// Window size for EccChip
    pub window_size: usize,
    /// Max number of verifications
    pub max_verif: usize,
    /// Marker
    pub _marker: PhantomData<F>,
}

impl<F: Field> SignVerifyChip<F> {
    /// Return a new SignVerifyChip
    pub fn new(max_verif: usize) -> Self {
        // TODO: Investigate if it is safe to use a random point as aux generator that
        // is choosen by the prover.  If this is unsafe, we will need to update the
        // EccChip to calculate an aux generator using the challange API.
        // https://github.com/privacy-scaling-explorations/halo2wrong/issues/53
        let mut rng = ChaCha20Rng::seed_from_u64(0);
        let aux_generator =
            <Secp256k1Affine as CurveAffine>::CurveExt::random(&mut rng).to_affine();
        Self {
            aux_generator,
            window_size: 2,
            max_verif,
            _marker: PhantomData,
        }
    }
}

impl<F: Field> Default for SignVerifyChip<F> {
    fn default() -> Self {
        Self {
            aux_generator: Secp256k1Affine::default(),
            window_size: 1,
            max_verif: 0,
            _marker: PhantomData::default(),
        }
    }
}

const NUMBER_OF_LIMBS: usize = 4;
const BIT_LEN_LIMB: usize = 72;
const BIT_LEN_LAST_LIMB: usize = 256 - (NUMBER_OF_LIMBS - 1) * BIT_LEN_LIMB;

/// SignVerify Configuration
#[derive(Debug, Clone)]
pub(crate) struct SignVerifyConfig {
    // ECDSA
    main_gate_config: MainGateConfig,
    range_config: RangeConfig,
    // RLC
    q_rlc_evm_word: Selector,
    q_rlc_keccak_input: Selector,
    rlc: Column<Advice>,
    // Keccak
    q_keccak: Selector,
    keccak_table: KeccakTable,
}

impl SignVerifyConfig {
    pub(crate) fn new<F: Field>(
        meta: &mut ConstraintSystem<F>,
        keccak_table: KeccakTable,
        challenges: Challenges<Expression<F>>,
    ) -> Self {
        // ECDSA config
        let (rns_base, rns_scalar) =
            GeneralEccChip::<Secp256k1Affine, F, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::rns();
        let main_gate_config = MainGate::<F>::configure(meta);
        let range_config = RangeChip::<F>::configure(
            meta,
            &main_gate_config,
            vec![BIT_LEN_LIMB / NUMBER_OF_LIMBS, 8],
            [rns_base.overflow_lengths(), rns_scalar.overflow_lengths()].concat(),
        );

        // RLC
        let q_rlc_evm_word = meta.selector();
        let q_rlc_keccak_input = meta.selector();
        let rlc = meta.advice_column();
        meta.enable_equality(rlc);

        Self::configure_rlc(
            meta,
            "evm_word_rlc",
            main_gate_config.clone(),
            q_rlc_evm_word,
            rlc,
            challenges.evm_word(),
        );
        Self::configure_rlc(
            meta,
            "keccak_input_rlc",
            main_gate_config.clone(),
            q_rlc_keccak_input,
            rlc,
            challenges.keccak_input(),
        );

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
            range_config,
            main_gate_config,
            keccak_table,
            q_rlc_evm_word,
            q_rlc_keccak_input,
            rlc,
            q_keccak,
        }
    }

    #[rustfmt::skip]
    fn configure_rlc<F: Field>(
        meta: &mut ConstraintSystem<F>,
        name: &'static str,
        main_gate_config: MainGateConfig,
        q_rlc: Selector,
        rlc: Column<Advice>,
        challenge: Expression<F>,
    ) {
        // Layout (take input with length 12 as an example)
        // | q_rlc |                          rlc                        |   a   |   b   |   c   |   d    |   e    |
        // | ----- | --------------------------------------------------- | ----- | ----- | ----- | ------ | ------ |
        // |   1   |                                                   0 |     0 |     0 |     0 |  be[0] |  be[1] |
        // |   1   |                                  be[0]*r^1 +  be[1] | be[2] | be[3] | be[4] |  be[5] |  be[6] |
        // |   1   | be[0]*r^6  + be[1]*r^5  + ... +  be[5]*r^1 +  be[6] | be[7] | be[8] | be[9] | be[10] | be[11] |
        // |   0   | be[0]*r^11 + be[1]*r^10 + ... + be[10]*r^1 + be[11] |       |       |       |        |        |
        //
        // Note that the first row of zeros will be enforced by copy constraint.
        meta.create_gate(name, |meta| {
            let q_rlc = meta.query_selector(q_rlc);
            let [a, b, c, d, e] = main_gate_config
                .advices()
                .map(|column| meta.query_advice(column, Rotation::cur()));
            let [rlc, rlc_next] = [Rotation::cur(), Rotation::next()]
                .map(|rotation| meta.query_advice(rlc, rotation));
            let inputs = [e, d, c, b, a, rlc];
            let powers_of_challenge = iter::successors(challenge.clone().into(), |power| {
                (challenge.clone() * power.clone()).into()
            })
            .take(inputs.len() - 1)
            .collect_vec();

            vec![q_rlc * (rlc_next - rlc::expr(&inputs, &powers_of_challenge))]
        });
    }
}

impl SignVerifyConfig {
    pub(crate) fn load_range<F: Field>(
        &self,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        let range_chip = RangeChip::<F>::new(self.range_config.clone());
        range_chip.load_table(layouter)
    }

    pub(crate) fn ecc_chip_config(&self) -> EccConfig {
        EccConfig::new(self.range_config.clone(), self.main_gate_config.clone())
    }

    pub(crate) fn integer_chip_config(&self) -> IntegerConfig {
        IntegerConfig::new(self.range_config.clone(), self.main_gate_config.clone())
    }
}

/// Term provides a wrapper of possible assigned cell with value or unassigned
/// value. It's similar to `AssignedCell` but with explicitly set value.
///
/// The reason to use `Term` instead of `AssignedCell` is because the value of
/// `AssignedCell` will always be `Value::unknown()` if the columns is not in
/// current phase, even the value assigned is not. And this behavior is due to
/// the fact that the `to` function in `assign_fixed` and `assign_advice` is
/// `FnMut` and will be guaranteed to be only called once.
#[derive(Clone, Debug)]
pub(crate) enum Term<F> {
    Assigned(Cell, Value<F>),
    Unassigned(Value<F>),
}

impl<F: Field> Term<F> {
    fn assigned(cell: Cell, value: Value<F>) -> Self {
        Self::Assigned(cell, value)
    }

    fn unassigned(value: Value<F>) -> Self {
        Self::Unassigned(value)
    }

    fn cell(&self) -> Option<Cell> {
        match self {
            Self::Assigned(cell, _) => Some(*cell),
            Self::Unassigned(_) => None,
        }
    }

    fn value(&self) -> Value<F> {
        match self {
            Self::Assigned(_, value) => *value,
            Self::Unassigned(value) => *value,
        }
    }
}

pub(crate) struct AssignedECDSA<F: Field> {
    pk_x_le: [AssignedValue<F>; 32],
    pk_y_le: [AssignedValue<F>; 32],
    msg_hash_le: [AssignedValue<F>; 32],
}

#[derive(Debug)]
pub(crate) struct AssignedSignatureVerify<F: Field> {
    pub(crate) address: AssignedValue<F>,
    pub(crate) msg_len: usize,
    pub(crate) msg_rlc: Value<F>,
    pub(crate) msg_hash_rlc: AssignedValue<F>,
}

// Return an array of bytes that corresponds to the little endian representation
// of the integer, adding the constraints to verify the correctness of the
// conversion (byte range check included).
fn integer_to_bytes_le<F: Field, FE: FieldExt>(
    ctx: &mut RegionCtx<'_, F>,
    range_chip: &RangeChip<F>,
    int: &AssignedInteger<FE, F, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
) -> Result<[AssignedValue<F>; 32], Error> {
    let bytes = int
        .limbs()
        .iter()
        .zip_eq([BIT_LEN_LIMB, BIT_LEN_LIMB, BIT_LEN_LIMB, BIT_LEN_LAST_LIMB])
        .map(|(limb, bit_len)| {
            range_chip
                .decompose(ctx, limb.as_ref().value().copied(), 8, bit_len)
                .map(|(_, byte)| byte)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect_vec();
    Ok(bytes.try_into().unwrap())
}

/// Helper structure pass around references to all the chips required for an
/// ECDSA veficication.
struct ChipsRef<'a, F: Field, const NUMBER_OF_LIMBS: usize, const BIT_LEN_LIMB: usize> {
    main_gate: &'a MainGate<F>,
    range_chip: &'a RangeChip<F>,
    ecc_chip: &'a GeneralEccChip<Secp256k1Affine, F, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    scalar_chip: &'a IntegerChip<secp256k1::Fq, F, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ecdsa_chip: &'a EcdsaChip<Secp256k1Affine, F, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
}

impl<F: Field> SignVerifyChip<F> {
    fn assign_aux(
        &self,
        ctx: &mut RegionCtx<'_, F>,
        ecc_chip: &mut GeneralEccChip<Secp256k1Affine, F, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
    ) -> Result<(), Error> {
        ecc_chip.assign_aux_generator(ctx, Value::known(self.aux_generator))?;
        ecc_chip.assign_aux(ctx, self.window_size, 1)?;
        Ok(())
    }

    fn assign_ecdsa(
        &self,
        ctx: &mut RegionCtx<F>,
        chips: &ChipsRef<F, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        sign_data: &SignData,
    ) -> Result<AssignedECDSA<F>, Error> {
        let SignData {
            signature,
            pk,
            msg: _,
            msg_hash,
        } = sign_data;
        let (sig_r, sig_s) = signature;

        let ChipsRef {
            main_gate: _,
            range_chip,
            ecc_chip,
            scalar_chip,
            ecdsa_chip,
        } = chips;

        let integer_r = ecc_chip.new_unassigned_scalar(Value::known(*sig_r));
        let integer_s = ecc_chip.new_unassigned_scalar(Value::known(*sig_s));
        let msg_hash = ecc_chip.new_unassigned_scalar(Value::known(*msg_hash));

        let r_assigned = scalar_chip.assign_integer(ctx, integer_r, Range::Remainder)?;
        let s_assigned = scalar_chip.assign_integer(ctx, integer_s, Range::Remainder)?;
        let sig = AssignedEcdsaSig {
            r: r_assigned,
            s: s_assigned,
        };

        let pk_in_circuit = ecc_chip.assign_point(ctx, Value::known(*pk))?;
        let pk_assigned = AssignedPublicKey {
            point: pk_in_circuit,
        };
        let msg_hash = scalar_chip.assign_integer(ctx, msg_hash, Range::Remainder)?;

        // Convert (msg_hash, pk_x, pk_y) integers to little endian bytes
        let msg_hash_le = integer_to_bytes_le(ctx, range_chip, &msg_hash)?;
        let pk_x = pk_assigned.point.x();
        let pk_x_le = integer_to_bytes_le(ctx, range_chip, pk_x)?;
        let pk_y = pk_assigned.point.y();
        let pk_y_le = integer_to_bytes_le(ctx, range_chip, pk_y)?;

        // Ref. spec SignVerifyChip 4. Verify the ECDSA signature
        ecdsa_chip.verify(ctx, &sig, &pk_assigned, &msg_hash)?;

        // TODO: Update once halo2wrong suports the following methods:
        // - `IntegerChip::assign_integer_from_bytes_le`
        // - `GeneralEccChip::assing_point_from_bytes_le`

        Ok(AssignedECDSA {
            pk_x_le,
            pk_y_le,
            msg_hash_le,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn assign_rlc_le(
        &self,
        config: &SignVerifyConfig,
        ctx: &mut RegionCtx<F>,
        chips: &ChipsRef<F, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        name: &str,
        q_rlc: Selector,
        challenge: Value<F>,
        inputs_le: impl IntoIterator<Item = Term<F>>,
    ) -> Result<AssignedCell<F, F>, Error> {
        let zero = chips.main_gate.assign_constant(ctx, F::zero())?;
        let columns = config.main_gate_config.advices();
        let inputs_le = inputs_le.into_iter().collect_vec();
        let inputs_be = iter::repeat_with(|| Term::assigned(zero.cell(), Value::known(F::zero())))
            .take(Integer::next_multiple_of(&inputs_le.len(), &columns.len()) - inputs_le.len())
            .chain(inputs_le.into_iter().rev())
            .collect_vec();

        let mut rlc = Value::known(F::zero());
        for (chunk_idx, chunk) in inputs_be.chunks_exact(columns.len()).enumerate() {
            ctx.enable(q_rlc)?;
            let assigned_rlc = ctx.assign_advice(|| "{name}_rlc[{chunk_idx}]", config.rlc, rlc)?;
            for ((idx, column), term) in (chunk_idx * chunk.len()..).zip(columns).zip(chunk) {
                let copied =
                    ctx.assign_advice(|| format!("{name}_byte[{idx}]"), column, term.value())?;
                if let Some(cell) = term.cell() {
                    ctx.constrain_equal(cell, copied.cell())?;
                }
            }
            if chunk_idx == 0 {
                ctx.constrain_equal(zero.cell(), assigned_rlc.cell())?;
            }
            rlc = iter::once(rlc)
                .chain(chunk.iter().map(|term| term.value()))
                .fold(Value::known(F::zero()), |acc, input| {
                    acc * challenge + input
                });
            ctx.next();
        }

        let assigned_rlc = ctx.assign_advice(|| "{name}_rlc", config.rlc, rlc)?;
        ctx.next();

        Ok(assigned_rlc)
    }

    fn enable_keccak_lookup(
        &self,
        config: &SignVerifyConfig,
        ctx: &mut RegionCtx<F>,
        is_address_zero: &AssignedCell<F, F>,
        pk_rlc: &AssignedCell<F, F>,
        pk_hash_rlc: &AssignedCell<F, F>,
    ) -> Result<(), Error> {
        let copy = |ctx: &mut RegionCtx<F>, name, column, assigned: &AssignedCell<F, F>| {
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
    fn assign_signature_verify(
        &self,
        config: &SignVerifyConfig,
        ctx: &mut RegionCtx<F>,
        chips: &ChipsRef<F, NUMBER_OF_LIMBS, BIT_LEN_LIMB>,
        sign_data: Option<&SignData>,
        assigned_ecdsa: &AssignedECDSA<F>,
        challenges: &Challenges<Value<F>>,
    ) -> Result<AssignedSignatureVerify<F>, Error> {
        let main_gate = chips.main_gate;

        let (padding, sign_data) = match sign_data {
            Some(sign_data) => (false, sign_data.clone()),
            None => (true, SignData::default()),
        };

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
        let pk_hash_hi = pk_hash[..12].to_vec();
        // Ref. spec SignVerifyChip 2. Verify that the first 20 bytes of the
        // pub_key_hash equal the address
        let (address, pk_hash_lo) = {
            let powers_of_256 =
                iter::successors(Some(F::one()), |coeff| Some(F::from(256) * coeff))
                    .take(20)
                    .collect_vec();
            let terms = pk_hash[12..]
                .iter()
                .zip(powers_of_256.into_iter().rev())
                .map(|(byte, coeff)| maingate::Term::Unassigned(*byte, coeff))
                .collect_vec();
            let (address, pk_hash_lo) =
                main_gate.decompose(ctx, &terms, F::zero(), |_, _| Ok(()))?;

            (
                address,
                pk_hash_lo
                    .into_iter()
                    .zip(pk_hash[12..].iter())
                    .map(|(assigned, byte)| Term::assigned(assigned.cell(), *byte))
                    .collect_vec(),
            )
        };
        let is_address_zero = main_gate.is_zero(ctx, &address)?;

        // Ref. spec SignVerifyChip 3. Verify that the signed message in the ecdsa_chip
        // with RLC encoding corresponds to msg_hash_rlc
        let msg_hash_rlc = {
            let zero = main_gate.assign_constant(ctx, F::zero())?;
            let assigned_msg_hash_le = assigned_ecdsa
                .msg_hash_le
                .iter()
                .map(|byte| main_gate.select(ctx, &zero, byte, &is_address_zero))
                .collect::<Result<Vec<_>, _>>()?;
            let msg_hash_le = (!padding)
                .then(|| sign_data.msg_hash.to_bytes())
                .unwrap_or_default()
                .map(|byte| Value::known(F::from(byte as u64)));
            self.assign_rlc_le(
                config,
                ctx,
                chips,
                "msg_hash",
                config.q_rlc_evm_word,
                challenges.evm_word(),
                assigned_msg_hash_le
                    .iter()
                    .zip(msg_hash_le)
                    .map(|(assigned, byte)| Term::assigned(assigned.cell(), byte)),
            )?
        };

        let pk_rlc = {
            let assigned_pk_le = iter::empty()
                .chain(&assigned_ecdsa.pk_y_le)
                .chain(&assigned_ecdsa.pk_x_le);
            let pk_le = iter::empty()
                .chain(sign_data.pk.y.to_bytes())
                .chain(sign_data.pk.x.to_bytes())
                .map(|byte| Value::known(F::from(byte as u64)));
            self.assign_rlc_le(
                config,
                ctx,
                chips,
                "pk_hash",
                config.q_rlc_keccak_input,
                challenges.keccak_input(),
                assigned_pk_le
                    .zip(pk_le)
                    .map(|(assigned, byte)| Term::assigned(assigned.cell(), byte)),
            )?
        };

        let pk_hash_rlc = self.assign_rlc_le(
            config,
            ctx,
            chips,
            "pk_hash_rlc",
            config.q_rlc_evm_word,
            challenges.evm_word(),
            iter::empty()
                .chain(pk_hash_lo.into_iter().rev())
                .chain(pk_hash_hi.into_iter().rev().map(Term::unassigned)),
        )?;

        self.enable_keccak_lookup(config, ctx, &is_address_zero, &pk_rlc, &pk_hash_rlc)?;

        Ok(AssignedSignatureVerify {
            address,
            msg_len: sign_data.msg.len(),
            msg_rlc: challenges
                .keccak_input()
                .map(|r| rlc::value(sign_data.msg.iter().rev(), r)),
            msg_hash_rlc,
        })
    }

    pub(crate) fn assign(
        &self,
        config: &SignVerifyConfig,
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
        let range_chip = RangeChip::new(config.range_config.clone());
        let mut ecc_chip = GeneralEccChip::<Secp256k1Affine, F, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(
            config.ecc_chip_config(),
        );
        let cloned_ecc_chip = ecc_chip.clone();
        let scalar_chip = cloned_ecc_chip.scalar_field_chip();

        layouter.assign_region(
            || "ecc chip aux",
            |region| self.assign_aux(&mut RegionCtx::new(region, 0), &mut ecc_chip),
        )?;

        let ecdsa_chip = EcdsaChip::new(ecc_chip.clone());

        let chips = ChipsRef {
            main_gate: &main_gate,
            range_chip: &range_chip,
            ecc_chip: &ecc_chip,
            scalar_chip,
            ecdsa_chip: &ecdsa_chip,
        };

        let assigned_ecdsas = layouter.assign_region(
            || "ecdsa chip verification",
            |region| {
                let mut assigned_ecdsas = Vec::new();
                let mut ctx = RegionCtx::new(region, 0);
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
                Ok(assigned_ecdsas)
            },
        )?;

        layouter.assign_region(
            || "signature address verify",
            |region| {
                let mut assigned_sig_verifs = Vec::new();
                let mut ctx = RegionCtx::new(region, 0);
                for (i, assigned_ecdsa) in assigned_ecdsas.iter().enumerate() {
                    let sign_data = signatures.get(i); // None when padding (enabled when address == 0)
                    let assigned_sig_verif = self.assign_signature_verify(
                        config,
                        &mut ctx,
                        &chips,
                        sign_data,
                        assigned_ecdsa,
                        challenges,
                    )?;
                    assigned_sig_verifs.push(assigned_sig_verif);
                }
                Ok(assigned_sig_verifs)
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
    use halo2_proofs::{
        circuit::SimpleFloorPlanner,
        dev::MockProver,
        halo2curves::{
            bn256::Fr,
            group::{Curve, Group},
            CurveAffine,
        },
        plonk::Circuit,
    };
    use pretty_assertions::assert_eq;
    use rand::{Rng, RngCore, SeedableRng};
    use rand_xorshift::XorShiftRng;
    use sha3::{Digest, Keccak256};

    #[derive(Clone, Debug)]
    struct TestCircuitSignVerifyConfig {
        sign_verify: SignVerifyConfig,
        challenges: Challenges,
    }

    impl TestCircuitSignVerifyConfig {
        pub(crate) fn new<F: Field>(meta: &mut ConstraintSystem<F>) -> Self {
            let keccak_table = KeccakTable::construct(meta);
            let challenges = Challenges::construct(meta);

            let sign_verify = {
                let challenges = challenges.exprs(meta);
                SignVerifyConfig::new(meta, keccak_table, challenges)
            };

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
        type Config = TestCircuitSignVerifyConfig;
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
        let mut rng = XorShiftRng::seed_from_u64(2);
        let aux_generator =
            <Secp256k1Affine as CurveAffine>::CurveExt::random(&mut rng).to_affine();

        // SignVerifyChip -> ECDSAChip -> MainGate instance column
        let circuit = TestCircuitSignVerify::<F> {
            sign_verify: SignVerifyChip {
                aux_generator,
                window_size: 2,
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
