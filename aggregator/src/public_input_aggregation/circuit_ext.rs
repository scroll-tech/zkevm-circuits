use eth_types::Field;
use snark_verifier_sdk::CircuitExt;
use zkevm_circuits::util::SubCircuit;

use crate::BatchHashCircuit;

impl<F: Field> CircuitExt<F> for BatchHashCircuit<F> {
    fn instances(&self) -> Vec<Vec<F>> {
        self.instance()
    }
}
