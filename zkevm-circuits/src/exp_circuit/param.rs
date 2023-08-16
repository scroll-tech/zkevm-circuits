/// The number of rows assigned for each step in an exponentiation trace.
/// It's max(MulAddChipRows, ExpCircuitRows) = max(8, 7) = 8
pub(crate) const OFFSET_INCREMENT: usize = 8usize;
/// The number of rows required for the exponentiation table within the circuit
/// for each step.
pub(crate) const ROWS_PER_STEP: usize = 4usize;
/// The gate "verify all but the last step" at constraint "`base_limb[i]` is the
/// same across all steps" uses rotation 10 in `exp_table.base_limb` which is
/// enabled with `q_usable`, which in turn is enabled in all steps.  This means
/// this circuit requires these extra rows after the last enabled `q_usable`.
pub(crate) const UNUSABLE_EXP_ROWS: usize = 10usize;
