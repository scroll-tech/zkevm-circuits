//! The ECC circuit is responsible for verifying ECC-related operations from precompiled contract
//! calls, namely, EcAdd, EcMul and EcPairing.

use std::marker::PhantomData;

use bus_mapping::{
    circuit_input_builder::{EcAddOp, EcMulOp, EcPairingOp},
    precompile::PrecompileCalls,
};
use eth_types::{Field, ToScalar};
use halo2_base::{
    gates::{GateInstructions, RangeInstructions},
    utils::modulus,
    Context, QuantumCell, SKIP_FIRST_PASS,
};
use halo2_ecc::{
    bn254::pairing::PairingChip,
    ecc::EccChip,
    fields::{
        fp::{FpConfig, FpStrategy},
        fp12::Fp12Chip,
        FieldChip,
    },
};
use halo2_proofs::{
    arithmetic::Field as Halo2Field,
    circuit::{Layouter, Value},
    halo2curves::bn256::{Fq, Fq12, Fr, G1Affine, G2Affine},
    plonk::{ConstraintSystem, Error, Expression},
};
use itertools::Itertools;
use log::error;

use crate::{
    table::{EccTable, LookupTable},
    util::{Challenges, SubCircuit, SubCircuitConfig},
    witness::Block,
};

mod dev;
mod test;
mod util;
use util::{
    EcAddAssigned, EcMulAssigned, EcOpsAssigned, EcPairingAssigned, G1Assigned, G1Decomposed,
    G2Assigned, G2Decomposed, ScalarAssigned, ScalarDecomposed,
};

use self::util::LOG_TOTAL_NUM_ROWS;

/// Arguments accepted to configure the EccCircuitConfig.
#[derive(Clone, Debug)]
pub struct EccCircuitConfigArgs<F: Field> {
    /// ECC table that is connected to the ECC circuit.
    pub ecc_table: EccTable,
    /// zkEVM challenge API.
    pub challenges: Challenges<Expression<F>>,
}

/// Config for the ECC circuit.
#[derive(Clone, Debug)]
pub struct EccCircuitConfig<F: Field> {
    /// Field config for halo2_proofs::halo2curves::bn256::Fq.
    fp_config: FpConfig<F, Fq>,
    /// Lookup table for I/Os to the EcAdd, EcMul and EcPairing operations.
    ecc_table: EccTable,

    /// Number of limbs to represent Fp.
    num_limbs: usize,
    /// Number of bits per limb.
    limb_bits: usize,

    _marker: PhantomData<F>,
}

impl<F: Field> SubCircuitConfig<F> for EccCircuitConfig<F> {
    type ConfigArgs = EccCircuitConfigArgs<F>;

    fn new(
        meta: &mut ConstraintSystem<F>,
        Self::ConfigArgs {
            ecc_table,
            challenges: _,
        }: Self::ConfigArgs,
    ) -> Self {
        let num_limbs = 3;
        let limb_bits = 88;
        let fp_config = FpConfig::configure(
            meta,
            FpStrategy::Simple,
            &[33], // num advice
            &[17], // num lookup advice
            1,     // num fixed
            13,    // lookup bits
            limb_bits,
            num_limbs,
            modulus::<Fq>(),
            0,
            LOG_TOTAL_NUM_ROWS as usize, // k
        );

        for column in <EccTable as LookupTable<F>>::advice_columns(&ecc_table) {
            meta.enable_equality(column);
        }

        Self {
            fp_config,
            ecc_table,
            num_limbs,
            limb_bits,
            _marker: PhantomData,
        }
    }
}

/// The ECC Circuit is a sub-circuit of the super circuit, responsible for verifying the following
/// ECC operations:
/// 1. Point Addition (R = P + Q)
/// 2. Scalar Multiplication (R = s.P)
/// 3. Pairing-based bilinear function
///
/// We follow a strategy to pre-allocate maximum number of cells for each of the above ECC
/// operations, which means a witness that exceeds the pre-allocated number of cells for any of the
/// operations will be invalid.
#[derive(Clone, Debug, Default)]
pub struct EccCircuit<F: Field, const XI_0: i64> {
    /// Maximum number of EcAdd operations supported in one instance of the ECC Circuit.
    pub max_add_ops: usize,
    /// Maximum number of scalar multiplication operations supported in one instance of the ECC
    /// Circuit.
    pub max_mul_ops: usize,
    /// Maximum number of pairing operations supported in one instance of the ECC Circuit.
    pub max_pairing_ops: usize,

    /// EcAdd operations provided as witness data to the ECC circuit.
    pub add_ops: Vec<EcAddOp>,
    /// EcMul operations provided as witness data to the ECC circuit.
    pub mul_ops: Vec<EcMulOp>,
    /// EcPairing operations provided as witness data to the ECC circuit.
    pub pairing_ops: Vec<EcPairingOp>,

    _marker: PhantomData<F>,
}

impl<F: Field, const XI_0: i64> EccCircuit<F, XI_0> {
    pub(crate) fn assign(
        &self,
        layouter: &mut impl Layouter<F>,
        config: &<Self as SubCircuit<F>>::Config,
        challenges: &Challenges<Value<F>>,
    ) -> Result<(), Error> {
        if self.add_ops.len() > self.max_add_ops
            || self.mul_ops.len() > self.max_mul_ops
            || self.pairing_ops.len() > self.max_pairing_ops
        {
            error!(
                "add ops = {}, mul ops = {}, pairing ops = {} > max add ops = {}, max mul ops = {}, max pairing ops = {}",
                self.add_ops.len(),
                self.mul_ops.len(),
                self.pairing_ops.len(),
                self.max_add_ops,
                self.max_mul_ops,
                self.max_pairing_ops,
            );
            return Err(Error::Synthesis);
        }

        // keccak powers of randomness.
        let keccak_powers = std::iter::successors(Some(Value::known(F::one())), |coeff| {
            Some(challenges.keccak_input() * coeff)
        })
        .take(4 * 192)
        .map(|x| QuantumCell::Witness(x))
        .collect_vec();

        let ecc_chip = EccChip::<F, FpConfig<F, Fq>>::construct(config.fp_config.clone());
        let fr_chip = FpConfig::<F, Fr>::construct(
            config.fp_config.range.clone(),
            config.limb_bits,
            config.num_limbs,
            modulus::<Fr>(),
        );
        let pairing_chip = PairingChip::construct(config.fp_config.clone());
        let fp12_chip =
            Fp12Chip::<F, FpConfig<F, Fq>, Fq12, XI_0>::construct(config.fp_config.clone());

        let mut first_pass = SKIP_FIRST_PASS;

        let assigned_ec_ops = layouter.assign_region(
            || "ecc circuit",
            |region| {
                if first_pass {
                    first_pass = false;
                    return Ok(EcOpsAssigned::default());
                }

                let mut ctx = config.fp_config.new_context(region);

                macro_rules! assign_ec_op {
                    ($op_type:ident, $ops:expr, $n_ops:expr, $assign_fn:ident) => {
                        $ops.iter()
                            .filter(|op| !op.skip_by_ecc_circuit())
                            .chain(std::iter::repeat(&$op_type::default()))
                            .take($n_ops)
                            .map(|op| {
                                self.$assign_fn(
                                    &mut ctx,
                                    &ecc_chip,
                                    &fr_chip,
                                    &pairing_chip,
                                    &fp12_chip,
                                    &keccak_powers,
                                    &op,
                                )
                            })
                            .collect_vec()
                    };
                }

                // P + Q == R
                let ec_adds_assigned =
                    assign_ec_op!(EcAddOp, self.add_ops, self.max_add_ops, assign_ec_add_op);

                // s.P = R
                let ec_muls_assigned =
                    assign_ec_op!(EcMulOp, self.mul_ops, self.max_mul_ops, assign_ec_mul_op);

                // e(G1 . G2) * ... * e(G1 . G2) -> Gt
                let ec_pairings_assigned = assign_ec_op!(
                    EcPairingOp,
                    self.pairing_ops,
                    self.max_pairing_ops,
                    assign_ec_pairing_op
                );

                Ok(EcOpsAssigned {
                    ec_adds_assigned,
                    ec_muls_assigned,
                    ec_pairings_assigned,
                })
            },
        )?;

        layouter.assign_region(
            || "expose ecc table",
            |mut region| {
                // handle EcAdd ops.
                for (idx, ec_add_assigned) in assigned_ec_ops.ec_adds_assigned.iter().enumerate() {
                    region.assign_fixed(
                        || "assign ecc_table op_type",
                        config.ecc_table.op_type,
                        idx,
                        || Value::known(F::from(u64::from(PrecompileCalls::Bn128Add))),
                    )?;
                    // P_x
                    ec_add_assigned.point_p.x_rlc.copy_advice(
                        &mut region,
                        config.ecc_table.arg1_rlc,
                        idx,
                    );
                    // P_y
                    ec_add_assigned.point_p.y_rlc.copy_advice(
                        &mut region,
                        config.ecc_table.arg2_rlc,
                        idx,
                    );
                    // Q_x
                    ec_add_assigned.point_q.x_rlc.copy_advice(
                        &mut region,
                        config.ecc_table.arg3_rlc,
                        idx,
                    );
                    // Q_y
                    ec_add_assigned.point_q.y_rlc.copy_advice(
                        &mut region,
                        config.ecc_table.arg4_rlc,
                        idx,
                    );
                    // R_x
                    ec_add_assigned.point_r.x_rlc.copy_advice(
                        &mut region,
                        config.ecc_table.output1_rlc,
                        idx,
                    );
                    // R_y
                    ec_add_assigned.point_r.y_rlc.copy_advice(
                        &mut region,
                        config.ecc_table.output2_rlc,
                        idx,
                    );
                    // input_rlc == 0
                    region.assign_advice(
                        || format!("input_rlc at offset = {idx}"),
                        config.ecc_table.input_rlc,
                        idx,
                        || Value::known(F::zero()),
                    )?;
                }

                // handle EcMul ops.
                for (idx, ec_mul_assigned) in assigned_ec_ops.ec_muls_assigned.iter().enumerate() {
                    let idx = idx + self.max_add_ops;
                    region.assign_fixed(
                        || "assign ecc_table op_type",
                        config.ecc_table.op_type,
                        idx,
                        || Value::known(F::from(u64::from(PrecompileCalls::Bn128Mul))),
                    )?;
                    // P_x
                    ec_mul_assigned.point_p.x_rlc.copy_advice(
                        &mut region,
                        config.ecc_table.arg1_rlc,
                        idx,
                    );
                    // P_y
                    ec_mul_assigned.point_p.y_rlc.copy_advice(
                        &mut region,
                        config.ecc_table.arg2_rlc,
                        idx,
                    );
                    // Scalar s
                    ec_mul_assigned
                        .scalar_s
                        .decomposed
                        .scalar
                        .native
                        .copy_advice(&mut region, config.ecc_table.arg3_rlc, idx);
                    // R_x
                    ec_mul_assigned.point_r.x_rlc.copy_advice(
                        &mut region,
                        config.ecc_table.output1_rlc,
                        idx,
                    );
                    // R_y
                    ec_mul_assigned.point_r.y_rlc.copy_advice(
                        &mut region,
                        config.ecc_table.output2_rlc,
                        idx,
                    );
                    for &col in [config.ecc_table.arg4_rlc, config.ecc_table.input_rlc].iter() {
                        region.assign_advice(
                            || format!("{col:?} at offset = {idx}"),
                            col,
                            idx,
                            || Value::known(F::zero()),
                        )?;
                    }
                }

                // handle EcPairing ops.
                for (idx, ec_pairing_assigned) in
                    assigned_ec_ops.ec_pairings_assigned.iter().enumerate()
                {
                    let idx = idx + self.max_add_ops + self.max_mul_ops;
                    region.assign_fixed(
                        || "assign ecc_table op_type",
                        config.ecc_table.op_type,
                        idx,
                        || Value::known(F::from(u64::from(PrecompileCalls::Bn128Pairing))),
                    )?;
                    // RLC(input_bytes)
                    ec_pairing_assigned.input_rlc.copy_advice(
                        &mut region,
                        config.ecc_table.input_rlc,
                        idx,
                    );
                    // success
                    ec_pairing_assigned.success.copy_advice(
                        &mut region,
                        config.ecc_table.output1_rlc,
                        idx,
                    );
                    for &col in [
                        config.ecc_table.arg1_rlc,
                        config.ecc_table.arg2_rlc,
                        config.ecc_table.arg3_rlc,
                        config.ecc_table.arg4_rlc,
                        config.ecc_table.output2_rlc,
                    ]
                    .iter()
                    {
                        region.assign_advice(
                            || format!("{col:?} at offset = {idx}"),
                            col,
                            idx,
                            || Value::known(F::zero()),
                        )?;
                    }
                }

                Ok(())
            },
        )?;

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn assign_ec_add_op(
        &self,
        ctx: &mut Context<F>,
        ecc_chip: &EccChip<F, FpConfig<F, Fq>>,
        _fr_chip: &FpConfig<F, Fr>,
        _pairing_chip: &PairingChip<F>,
        _fp12_chip: &Fp12Chip<F, FpConfig<F, Fq>, Fq12, XI_0>,
        powers_of_rand: &[QuantumCell<F>],
        op: &EcAddOp,
    ) -> EcAddAssigned<F> {
        let point_p = self.assign_g1(ctx, ecc_chip, op.p, powers_of_rand);
        let point_q = self.assign_g1(ctx, ecc_chip, op.q, powers_of_rand);
        let point_r = self.assign_g1(ctx, ecc_chip, op.r, powers_of_rand);

        // We follow the approach mentioned below to handle many edge cases for the points P, Q and
        // R so that we can maintain the same fixed and permutation columns and reduce the overall
        // validation process from the EVM Circuit.
        //
        // To check the validity of P + Q == R, we check:
        // r + P + Q - R == r
        // where r is a random point on the curve.
        //
        // We cover cases such as:
        // - P == (0, 0) and/or Q == (0, 0)
        // - P == -Q, i.e. P + Q == R == (0, 0)

        let rand_point = ecc_chip.load_random_point::<G1Affine>(ctx);

        // check if P == (0, 0), Q == (0, 0), R == (0, 0)
        let p_x_is_zero = ecc_chip
            .field_chip
            .is_zero(ctx, &point_p.decomposed.ec_point.x);
        let p_y_is_zero = ecc_chip
            .field_chip
            .is_zero(ctx, &point_p.decomposed.ec_point.y);
        let q_x_is_zero = ecc_chip
            .field_chip
            .is_zero(ctx, &point_q.decomposed.ec_point.x);
        let q_y_is_zero = ecc_chip
            .field_chip
            .is_zero(ctx, &point_q.decomposed.ec_point.y);
        let r_x_is_zero = ecc_chip
            .field_chip
            .is_zero(ctx, &point_r.decomposed.ec_point.x);
        let r_y_is_zero = ecc_chip
            .field_chip
            .is_zero(ctx, &point_r.decomposed.ec_point.y);
        let point_p_is_zero = ecc_chip.field_chip.range().gate().and(
            ctx,
            QuantumCell::Existing(p_x_is_zero),
            QuantumCell::Existing(p_y_is_zero),
        );
        let point_q_is_zero = ecc_chip.field_chip.range().gate().and(
            ctx,
            QuantumCell::Existing(q_x_is_zero),
            QuantumCell::Existing(q_y_is_zero),
        );
        let point_r_is_zero = ecc_chip.field_chip.range().gate().and(
            ctx,
            QuantumCell::Existing(r_x_is_zero),
            QuantumCell::Existing(r_y_is_zero),
        );

        // sum1 = if P == (0, 0) then r else r + P
        let sum1 = ecc_chip.add_unequal(ctx, &rand_point, &point_p.decomposed.ec_point, true);
        let sum1 = ecc_chip.select(ctx, &rand_point, &sum1, &point_p_is_zero);

        // sum2 = if Q == (0, 0) then sum1 else sum1 + Q
        let sum2 = ecc_chip.add_unequal(ctx, &sum1, &point_q.decomposed.ec_point, true);
        let sum2 = ecc_chip.select(ctx, &sum1, &sum2, &point_q_is_zero);

        // sum3 = if R == (0, 0) then sum2 else sum2 - R
        let sum3 = ecc_chip.sub_unequal(ctx, &sum2, &point_r.decomposed.ec_point, true);
        let sum3 = ecc_chip.select(ctx, &sum2, &sum3, &point_r_is_zero);

        ecc_chip.assert_equal(ctx, &rand_point, &sum3);

        EcAddAssigned {
            point_p,
            point_q,
            point_r,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn assign_ec_mul_op(
        &self,
        ctx: &mut Context<F>,
        ecc_chip: &EccChip<F, FpConfig<F, Fq>>,
        fr_chip: &FpConfig<F, Fr>,
        _pairing_chip: &PairingChip<F>,
        _fp12_chip: &Fp12Chip<F, FpConfig<F, Fq>, Fq12, XI_0>,
        powers_of_rand: &[QuantumCell<F>],
        op: &EcMulOp,
    ) -> EcMulAssigned<F> {
        let point_p = self.assign_g1(ctx, ecc_chip, op.p, powers_of_rand);
        let scalar_s = self.assign_fr(ctx, fr_chip, op.s);
        let point_r = self.assign_g1(ctx, ecc_chip, op.r, powers_of_rand);
        let point_r_got = ecc_chip.scalar_mult(
            ctx,
            &point_p.decomposed.ec_point,
            &scalar_s.decomposed.scalar.limbs().to_vec(),
            fr_chip.limb_bits,
            4, // TODO: window bits?
        );
        ecc_chip.assert_equal(ctx, &point_r.decomposed.ec_point, &point_r_got);
        EcMulAssigned {
            point_p,
            scalar_s,
            point_r,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn assign_ec_pairing_op(
        &self,
        ctx: &mut Context<F>,
        ecc_chip: &EccChip<F, FpConfig<F, Fq>>,
        _fr_chip: &FpConfig<F, Fr>,
        pairing_chip: &PairingChip<F>,
        fp12_chip: &Fp12Chip<F, FpConfig<F, Fq>, Fq12, XI_0>,
        powers_of_rand: &[QuantumCell<F>],
        op: &EcPairingOp,
    ) -> EcPairingAssigned<F> {
        let g1s = op
            .inputs
            .iter()
            .map(|i| {
                let (x_cells, y_cells) = self.decompose_g1(i.0);
                let decomposed = G1Decomposed {
                    ec_point: pairing_chip.load_private_g1(ctx, Value::known(i.0)),
                    x_cells: x_cells.clone(),
                    y_cells: y_cells.clone(),
                };
                G1Assigned {
                    decomposed,
                    x_rlc: pairing_chip.fp_chip.range.gate.inner_product(
                        ctx,
                        x_cells,
                        powers_of_rand.iter().cloned(),
                    ),
                    y_rlc: pairing_chip.fp_chip.range.gate.inner_product(
                        ctx,
                        y_cells,
                        powers_of_rand.iter().cloned(),
                    ),
                }
            })
            .collect_vec();
        let g2s = op
            .inputs
            .iter()
            .map(|i| {
                let [x_c0_cells, x_c1_cells, y_c0_cells, y_c1_cells] = self.decompose_g2(i.1);
                let decomposed = G2Decomposed {
                    ec_point: pairing_chip.load_private_g2(ctx, Value::known(i.1)),
                    x_c0_cells: x_c0_cells.clone(),
                    x_c1_cells: x_c1_cells.clone(),
                    y_c0_cells: y_c0_cells.clone(),
                    y_c1_cells: y_c1_cells.clone(),
                };
                G2Assigned {
                    decomposed,
                    x_c0_rlc: pairing_chip.fp_chip.range.gate.inner_product(
                        ctx,
                        x_c0_cells,
                        powers_of_rand.iter().cloned(),
                    ),
                    x_c1_rlc: pairing_chip.fp_chip.range.gate.inner_product(
                        ctx,
                        x_c1_cells,
                        powers_of_rand.iter().cloned(),
                    ),
                    y_c0_rlc: pairing_chip.fp_chip.range.gate.inner_product(
                        ctx,
                        y_c0_cells,
                        powers_of_rand.iter().cloned(),
                    ),
                    y_c1_rlc: pairing_chip.fp_chip.range.gate.inner_product(
                        ctx,
                        y_c1_cells,
                        powers_of_rand.iter().cloned(),
                    ),
                }
            })
            .collect_vec();

        // RLC over the entire input bytes.
        let input_cells = std::iter::empty()
            .chain(g1s.iter().map(|g1| g1.decomposed.x_cells.clone()))
            .chain(g1s.iter().map(|g1| g1.decomposed.y_cells.clone()))
            .chain(g2s.iter().map(|g2| g2.decomposed.x_c0_cells.clone()))
            .chain(g2s.iter().map(|g2| g2.decomposed.x_c1_cells.clone()))
            .chain(g2s.iter().map(|g2| g2.decomposed.y_c0_cells.clone()))
            .chain(g2s.iter().map(|g2| g2.decomposed.y_c1_cells.clone()))
            .flatten()
            .collect::<Vec<QuantumCell<F>>>();
        let input_rlc = pairing_chip.fp_chip.range.gate.inner_product(
            ctx,
            input_cells,
            powers_of_rand.iter().cloned(),
        );

        let pairs = g1s
            .iter()
            .zip(g2s.iter())
            .map(|(g1, g2)| (&g1.decomposed.ec_point, &g2.decomposed.ec_point))
            .collect_vec();

        let success = {
            let gt = {
                let gt = pairing_chip.multi_miller_loop(ctx, pairs);
                pairing_chip.final_exp(ctx, &gt)
            };
            // whether pairing check was successful.
            let one = fp12_chip.load_constant(ctx, Fq12::one());
            fp12_chip.is_equal(ctx, &gt, &one)
        };

        ecc_chip.field_chip().range().gate().assert_equal(
            ctx,
            QuantumCell::Existing(success),
            QuantumCell::Witness(Value::known(
                op.output.to_scalar().expect("EcPairing output = {0, 1}"),
            )),
        );

        EcPairingAssigned {
            g1s,
            g2s,
            input_rlc,
            success,
        }
    }

    fn assign_g1(
        &self,
        ctx: &mut Context<F>,
        fp_chip: &EccChip<F, FpConfig<F, Fq>>,
        g1: G1Affine,
        powers_of_rand: &[QuantumCell<F>],
    ) -> G1Assigned<F> {
        let ec_point = fp_chip.load_private(ctx, (Value::known(g1.x), Value::known(g1.y)));
        let (x_cells, y_cells) = self.decompose_g1(g1);
        let decomposed = G1Decomposed {
            ec_point,
            x_cells: x_cells.clone(),
            y_cells: x_cells.clone(),
        };
        G1Assigned {
            decomposed,
            x_rlc: fp_chip.field_chip().range.gate.inner_product(
                ctx,
                x_cells,
                powers_of_rand.iter().cloned(),
            ),
            y_rlc: fp_chip.field_chip().range.gate.inner_product(
                ctx,
                y_cells,
                powers_of_rand.iter().cloned(),
            ),
        }
    }

    fn decompose_g1(&self, g1: G1Affine) -> (Vec<QuantumCell<F>>, Vec<QuantumCell<F>>) {
        (
            g1.x.to_bytes()
                .iter()
                .map(|&x| QuantumCell::Witness(Value::known(F::from(u64::from(x)))))
                .collect_vec(),
            g1.y.to_bytes()
                .iter()
                .map(|&y| QuantumCell::Witness(Value::known(F::from(u64::from(y)))))
                .collect_vec(),
        )
    }

    fn decompose_g2(&self, g2: G2Affine) -> [Vec<QuantumCell<F>>; 4] {
        [
            g2.x.c0
                .to_bytes()
                .iter()
                .map(|&x| QuantumCell::Witness(Value::known(F::from(u64::from(x)))))
                .collect_vec(),
            g2.x.c1
                .to_bytes()
                .iter()
                .map(|&x| QuantumCell::Witness(Value::known(F::from(u64::from(x)))))
                .collect_vec(),
            g2.y.c0
                .to_bytes()
                .iter()
                .map(|&y| QuantumCell::Witness(Value::known(F::from(u64::from(y)))))
                .collect_vec(),
            g2.y.c1
                .to_bytes()
                .iter()
                .map(|&y| QuantumCell::Witness(Value::known(F::from(u64::from(y)))))
                .collect_vec(),
        ]
    }

    fn assign_fr(
        &self,
        ctx: &mut Context<F>,
        fr_chip: &FpConfig<F, Fr>,
        s: Fr,
    ) -> ScalarAssigned<F> {
        let scalar = fr_chip.load_private(ctx, FpConfig::<F, Fr>::fe_to_witness(&Value::known(s)));
        let decomposed = ScalarDecomposed { scalar };
        ScalarAssigned { decomposed }
    }
}

impl<F: Field, const XI_0: i64> SubCircuit<F> for EccCircuit<F, XI_0> {
    type Config = EccCircuitConfig<F>;

    fn new_from_block(block: &Block<F>) -> Self {
        Self {
            max_add_ops: block.circuits_params.max_ec_ops.ec_add,
            max_mul_ops: block.circuits_params.max_ec_ops.ec_mul,
            max_pairing_ops: block.circuits_params.max_ec_ops.ec_pairing,
            add_ops: block.get_ec_add_ops(),
            mul_ops: block.get_ec_mul_ops(),
            pairing_ops: block.get_ec_pairing_ops(),
            _marker: PhantomData,
        }
    }

    fn synthesize_sub(
        &self,
        config: &Self::Config,
        challenges: &Challenges<Value<F>>,
        layouter: &mut impl Layouter<F>,
    ) -> Result<(), Error> {
        config.fp_config.range.load_lookup_table(layouter)?;
        self.assign(layouter, config, challenges)?;
        Ok(())
    }

    fn min_num_rows_block(_block: &Block<F>) -> (usize, usize) {
        unimplemented!()
    }
}
