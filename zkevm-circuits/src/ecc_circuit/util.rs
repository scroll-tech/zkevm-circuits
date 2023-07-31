use eth_types::Field;
use halo2_base::{AssignedValue, QuantumCell};
use halo2_ecc::{bigint::CRTInteger, ecc::EcPoint, fields::FieldExtPoint};

// Total number of rows allowable for ECC circuit
pub const LOG_TOTAL_NUM_ROWS: u32 = 20;

// Cell usage accounting for EcAdd, EcMul and EcPairing
// Roud up to nearest 100
pub(super) const EC_ADD_CELLS: usize = 6_900; // actual: 6_851
pub(super) const EC_MUL_CELLS: usize = 405_500; // actual: 405_476
pub(super) const EC_PAIRING_CELLS: usize = 6_627_500; // actual: 6_627_442
pub(super) const COLUMN_NUM_LIMIT: usize = 150; // Max number of columns allowed

pub struct G1Decomposed<F: Field> {
    pub ec_point: EcPoint<F, CRTInteger<F>>,
    pub x_cells: Vec<QuantumCell<F>>,
    pub y_cells: Vec<QuantumCell<F>>,
}

pub struct G1Assigned<F: Field> {
    pub decomposed: G1Decomposed<F>,
    pub x_rlc: AssignedValue<F>,
    pub y_rlc: AssignedValue<F>,
}

pub struct ScalarDecomposed<F: Field> {
    pub scalar: CRTInteger<F>,
}

pub struct ScalarAssigned<F: Field> {
    pub decomposed: ScalarDecomposed<F>,
}

pub struct G2Decomposed<F: Field> {
    pub ec_point: EcPoint<F, FieldExtPoint<CRTInteger<F>>>,
    pub x_c0_cells: Vec<QuantumCell<F>>,
    pub x_c1_cells: Vec<QuantumCell<F>>,
    pub y_c0_cells: Vec<QuantumCell<F>>,
    pub y_c1_cells: Vec<QuantumCell<F>>,
}

pub struct G2Assigned<F: Field> {
    pub decomposed: G2Decomposed<F>,
    pub x_c0_rlc: AssignedValue<F>,
    pub x_c1_rlc: AssignedValue<F>,
    pub y_c0_rlc: AssignedValue<F>,
    pub y_c1_rlc: AssignedValue<F>,
}

pub struct EcAddAssigned<F: Field> {
    pub point_p: G1Assigned<F>,
    pub point_q: G1Assigned<F>,
    pub point_r: G1Assigned<F>,
}

pub struct EcMulAssigned<F: Field> {
    pub point_p: G1Assigned<F>,
    pub scalar_s: ScalarAssigned<F>,
    pub point_r: G1Assigned<F>,
}

pub struct EcPairingAssigned<F: Field> {
    pub g1s: Vec<G1Assigned<F>>,
    pub g2s: Vec<G2Assigned<F>>,
    pub input_rlc: AssignedValue<F>,
    pub success: AssignedValue<F>,
}

#[derive(Default)]
pub struct EcOpsAssigned<F: Field> {
    pub ec_adds_assigned: Vec<EcAddAssigned<F>>,
    pub ec_muls_assigned: Vec<EcMulAssigned<F>>,
    pub ec_pairings_assigned: Vec<EcPairingAssigned<F>>,
}
