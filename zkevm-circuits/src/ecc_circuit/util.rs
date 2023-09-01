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

/// Decomposed state of a G1 curve point.
pub(super) struct G1Decomposed<F: Field> {
    /// EcPoint on G1.
    pub ec_point: EcPoint<F, CRTInteger<F>>,
    /// Cells for the x-coordinate of the G1 curve point in LE format.
    pub x_cells: Vec<QuantumCell<F>>,
    /// Cells for the y-coordinate of the G1 curve point in LE format.
    pub y_cells: Vec<QuantumCell<F>>,
}

/// State of the G1 curve point after RLC operations.
pub(super) struct G1Assigned<F: Field> {
    /// RLC of x-coordinate that will be copied to the ECC Table.
    pub x_rlc: AssignedValue<F>,
    /// RLC of y-coordinate that will be copied to the ECC Table.
    pub y_rlc: AssignedValue<F>,
}

/// State of a scalar field element. Since the scalar fits within the field, we don't need to take
/// RLC over its bytes/cells. Hence we can decompose and assign the scalar in the first phase.
#[derive(Clone)]
pub(super) struct ScalarAssigned<F: Field> {
    pub scalar: CRTInteger<F>,
}

/// Decomposed state of a G2 curve point.
pub(super) struct G2Decomposed<F: Field> {
    /// The assigned EcPoint.
    pub ec_point: EcPoint<F, FieldExtPoint<CRTInteger<F>>>,
    /// Cells for the coeff 0 of x-coordinate of the G2 curve point in LE format.
    pub x_c0_cells: Vec<QuantumCell<F>>,
    /// Cells for the coeff 1 of x-coordinate of the G2 curve point in LE format.
    pub x_c1_cells: Vec<QuantumCell<F>>,
    /// Cells for the coeff 0 of y-coordinate of the G2 curve point in LE format.
    pub y_c0_cells: Vec<QuantumCell<F>>,
    /// Cells for the coeff 1 of y-coordinate of the G2 curve point in LE format.
    pub y_c1_cells: Vec<QuantumCell<F>>,
}

/// State of EcAdd operation post first phase.
pub(super) struct EcAddDecomposed<F: Field> {
    pub is_valid: AssignedValue<F>,
    pub point_p: G1Decomposed<F>,
    pub point_q: G1Decomposed<F>,
    pub point_r: G1Decomposed<F>,
}

/// State of EcAdd operation post second phase.
pub(super) struct EcAddAssigned<F: Field> {
    pub is_valid: AssignedValue<F>,
    pub point_p: G1Assigned<F>,
    pub point_q: G1Assigned<F>,
    pub point_r: G1Assigned<F>,
}

/// State of EcMul operation post first phase.
pub(super) struct EcMulDecomposed<F: Field> {
    pub is_valid: AssignedValue<F>,
    pub point_p: G1Decomposed<F>,
    pub scalar_s: ScalarAssigned<F>,
    pub point_r: G1Decomposed<F>,
}

/// State of EcMul operation post second phase.
pub(super) struct EcMulAssigned<F: Field> {
    pub is_valid: AssignedValue<F>,
    pub point_p: G1Assigned<F>,
    pub scalar_s: ScalarAssigned<F>,
    pub point_r: G1Assigned<F>,
}

/// State of EcPairing operation post first phase.
pub(super) struct EcPairingDecomposed<F: Field> {
    pub is_valid: AssignedValue<F>,
    pub input_cells: Vec<QuantumCell<F>>,
    pub success: AssignedValue<F>,
}

/// State of EcPairing operation post second phase.
pub(super) struct EcPairingAssigned<F: Field> {
    pub is_valid: AssignedValue<F>,
    /// RLC of (G1, G2) pairs.
    pub input_rlc: AssignedValue<F>,
    pub success: AssignedValue<F>,
}

/// Wrapper struct that holds all the ecXX states post second phase.
#[derive(Default)]
pub(super) struct EcOpsAssigned<F: Field> {
    pub ec_adds_assigned: Vec<EcAddAssigned<F>>,
    pub ec_muls_assigned: Vec<EcMulAssigned<F>>,
    pub ec_pairings_assigned: Vec<EcPairingAssigned<F>>,
}
