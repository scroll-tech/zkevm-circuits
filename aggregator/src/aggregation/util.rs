use halo2_proofs::halo2curves::FieldExt;
use snark_verifier::loader::halo2::halo2_ecc::halo2_base::{
    gates::{flex_gate::FlexGateConfig, GateInstructions},
    AssignedValue, Context, QuantumCell,
};

/// Input values a and b, return a boolean cell a < b
pub(crate) fn is_smaller_than<F: FieldExt>(
    gate_config: &FlexGateConfig<F>,
    ctx: &mut Context<F>,
    a: &AssignedValue<F>,
    b: &AssignedValue<F>,
) -> AssignedValue<F> {
    // compute bit decomposition of a - b
    // if a < b there will be a wraparound and therefore the last bit will be 1
    // else the last bit will be 0
    let c = gate_config.sub(ctx, QuantumCell::Existing(*a), QuantumCell::Existing(*b));
    let c_bits = gate_config.num_to_bits(ctx, &c, 254);

    println!(
        "a {:?}, b {:?}, c_bits {:?}",
        a.value,
        b.value,
        c_bits.last().unwrap().value
    );

    *c_bits.last().unwrap()
}
