//! Bus module.

/// Bus chip that check the integrity of all bus accesses.
pub mod bus_chip;

/// The bus builder collects all the ports into a bus.
pub mod bus_builder;

/// A chip to access the bus.
pub mod bus_port;

/// A chip to access the bus, with batching.
pub mod port_multi;

/// A chip to expose a lookup table on a bus.
pub mod bus_lookup;

/// This module encodes messages into terms.
pub mod bus_codec;

/// This module helps ports with their assignments.
mod batch_assigner;

/// Utility functions.
mod util;

#[cfg(test)]
mod tests;

use eth_types::Field;
