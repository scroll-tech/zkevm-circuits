/// Circuit implementation of aggregation circuit.
mod circuit;
/// CircuitExt implementation of compression circuit.
mod circuit_ext;
/// Config for aggregation circuit
mod config;
/// utilities
mod util;

pub use circuit::AggregationCircuit;
pub use config::AggregationConfig;
