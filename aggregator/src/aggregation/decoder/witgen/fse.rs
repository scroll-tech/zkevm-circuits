
use std::collections::BTreeMap;
use std::io::{Result, Read};

use bitstream_io::{
    read::{BitRead, BitReader},
    LittleEndian, BigEndian,
};

use super::params::*;

/// naming fse symbol
pub type FSESymbol = u32;

/// A single row in the FSE table.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FseTableRow {
    /// The FSE state at this row in the FSE table.
    pub state: u64,
    /// The baseline associated with this state.
    pub baseline: u64,
    /// The number of bits to be read from the input bitstream at this state.
    pub num_bits: u64,
    /// The symbol emitted by the FSE table at this state.
    pub symbol: FSESymbol,
}

/// entry type in fse table (accury log or symbol)
#[derive(Clone, Copy, Debug)]
pub enum FSETableEntry {
    AccuryLog,
    Symbol(FSESymbol),
    // it tell the prob 0 symbol and n(u8) next symbol
    RepeatSym((FSESymbol, u8)),
    Trailing,
}

/// bit boundary and value for parsing FseHeader
#[derive(Clone, Debug)]
pub struct FseTableEntry {
    /// the symbol parsed in header
    pub symbol: FSETableEntry,
    /// the bit offset in header
    pub bit_offset: usize,
    /// the read value for symbol
    pub value: u32,
}

/// Auxiliary data accompanying the FSE table's witness values.
#[derive(Clone, Debug)]
pub struct FseAuxiliaryTableData {
    /// The FSE's accuracy log, 
    pub accuracy_log: u8,
    /// A map from FseSymbol (weight) to states, also including fields for that state, for
    /// instance, the baseline and the number of bits to read from the FSE bitstream.
    ///
    /// For each symbol, the states are in strictly increasing order.
    pub sym_to_states: BTreeMap<FSESymbol, Vec<FseTableRow>>,
}

/// Another form of Fse table that has state as key instead of the FseSymbol.
/// In decoding, symbols are emitted from state-chaining.
/// This representation makes it easy to look up decoded symbol from current state.   
/// Map<state, (symbol, baseline, num_bits)>.
type FseStateMapping = BTreeMap<u64, (FSESymbol, u32, u8)>;

impl FseAuxiliaryTableData {

    /// calc the table size, i.e. 1 << AL (accuracy log).
    pub fn table_size(&self) -> u64 {1 << self.accuracy_log}

    /// Convert an FseAuxiliaryTableData into a state-mapped representation.
    /// This makes it easier to lookup state-chaining during decoding.
    pub fn parse_state_table(&self) -> FseStateMapping {
        let rows: Vec<FseTableRow> = self
            .sym_to_states
            .values()
            .flat_map(|v| v.clone())
            .collect();
        let mut state_table: FseStateMapping = BTreeMap::new();

        for row in rows {
            state_table.insert(row.state, (row.symbol as FSESymbol, row.baseline as u32, row.num_bits as u8));
        }

        state_table
    }

}

struct FseTableProcessing (Vec<FseTableEntry>, FseAuxiliaryTableData);

impl FseTableProcessing {
    
    #[allow(non_snake_case)]
    /// While we reconstruct an FSE table from a bitstream, we do not know before reconstruction
    /// how many exact bytes we would finally be reading.
    ///
    /// The number of bytes actually read while reconstruction is called `t` and is returned along
    /// with the reconstructed FSE table. After processing the entire bitstream to reconstruct the
    /// FSE table, if the read bitstream was not byte aligned, then we discard the 1..8 bits from
    /// the last byte that we read from.
    pub fn reconstruct(data: &[u8]) -> std::io::Result<Self> {
        use itertools::Itertools;
        use super::util::{reader_read_variable_bit_packing, smaller_powers_of_two};

        // construct little-endian bit-reader.
        let mut reader = BitReader::endian(data, LittleEndian);
        // number of bits read by the bit-reader from the bistream.
        let mut offset = 0;

        let accuracy_log = {
            offset += 4;
            reader.read::<u8>(offset)? + 5
        };

        let mut entries = vec![
            FseTableEntry{
                symbol: FSETableEntry::AccuryLog,
                bit_offset: offset as usize,
                value: accuracy_log as u32,
            },
        ];
        //    (offset, accuracy_log as u64 - 5));
        let table_size = 1 << accuracy_log;

        let mut sym_to_states = BTreeMap::new();
        let mut R = table_size;
        let mut state = 0x00;
        let mut symbol = FSESymbol::default();
        while R > 0 {
            // number of bits and value read from the variable bit-packed data.
            let (n_bits_read, value) = reader_read_variable_bit_packing(
                &mut reader, R + 1)?;
            offset += n_bits_read;

            let entry = FseTableEntry{
                    symbol: FSETableEntry::Symbol(symbol),
                    bit_offset: offset as usize,
                    value: value as u32,
                };

            if value == 0 {
                unimplemented!("value=0 => prob=-1: scenario unimplemented");
            }

            let N = value - 1;

            // When a symbol has a probability of zero, it is followed by a 2-bits repeat flag. This
            // repeat flag tells how many probabilities of zeroes follow the current one. It
            // provides a number ranging from 0 to 3. If it is a 3, another 2-bits repeat flag
            // follows, and so on.
            if N == 0 {
                sym_to_states.insert(symbol, vec![]);
                entries.push(entry);
                symbol += 1;
                loop {
                    let repeat_bits = reader.read::<u8>(2)?;
                    offset += 2;
                    entries.push(
                        FseTableEntry{
                            symbol: FSETableEntry::RepeatSym((symbol, repeat_bits)),
                            bit_offset: offset as usize,
                            value: repeat_bits as u32,
                        });

                    for k in 0..repeat_bits {
                        sym_to_states.insert(symbol + (k as FSESymbol), vec![]);
                        symbol += 1;
                    }

                    if repeat_bits < 3 {
                        break;
                    }
                }
            }

            if N >= 1 {
                let states = std::iter::once(state)
                .chain((1..N).map(|_| {
                    state += (table_size >> 1) + (table_size >> 3) + 3;
                    state &= table_size - 1;
                    state
                }))
                .sorted()
                .collect::<Vec<u64>>();
                let (smallest_spot_idx, nbs) = smaller_powers_of_two(table_size, N);
                let baselines = if N == 1 {
                    vec![0x00]
                } else {
                    let mut rotated_nbs = nbs.clone();
                    rotated_nbs.rotate_left(smallest_spot_idx);

                    let mut baselines = std::iter::once(0x00)
                        .chain(rotated_nbs.iter().scan(0x00, |baseline, nb| {
                            *baseline += 1 << nb;
                            Some(*baseline)
                        }))
                        .take(N as usize)
                        .collect::<Vec<u64>>();

                    baselines.rotate_right(smallest_spot_idx);
                    baselines
                };
                sym_to_states.insert(
                    symbol,
                    states
                        .iter()
                        .zip(nbs.iter())
                        .zip(baselines.iter())
                        .map(|((&state, &nb), &baseline)| FseTableRow {
                            state,
                            num_bits: nb,
                            baseline,
                            symbol: symbol.into(),
                        })
                        .collect(),
                );

                // update the total number of bits read so far.

                entries.push(FseTableEntry{
                    symbol: FSETableEntry::Symbol(symbol),
                    bit_offset: offset as usize,
                    value: value as u32,
                });

                // increment symbol.
                symbol += 1;

                // update state.
                state += (table_size >> 1) + (table_size >> 3) + 3;
                state &= table_size - 1;
            }

            // remove N slots from a total of R.
            R -= N;
        }

        // ignore any bits left to be read until byte-aligned.
        // this bits has no effect 
        let t = (((offset as usize) - 1) / N_BITS_PER_BYTE) + 1;

        // read the trailing section
        if t * N_BITS_PER_BYTE > (offset as usize) {
            let bits_remaining = t * N_BITS_PER_BYTE - offset as usize;
            entries.push(FseTableEntry{
                symbol: FSETableEntry::Trailing,
                bit_offset: t * N_BITS_PER_BYTE,
                value: reader.read::<u8>(bits_remaining as u32)? as u32,
            });
        }

        Ok(Self(
            entries,
            FseAuxiliaryTableData {
                accuracy_log,
                sym_to_states,
            },
        ))
    }

}

/// the processing detail for fse symbols in bitstream, can
/// used for generate witness for parsing circuit
#[derive(Clone, Debug)]
pub struct FSESymbolProcessing{
    base_line: u32,
    next_bits: usize,
    last_offset: usize,
    fse_state_mapping: FseStateMapping,
}

/// the data help for building a row in parse circuit
pub type WitnessRow = (
    FseTableRow,
    usize, // the begin offset of bit index
    usize, // the end offset of bit index
);

impl FSESymbolProcessing {

    /// beginning from the new fse encoding
    pub fn start(
        fse_table: &FseAuxiliaryTableData,
        initial_offset: Option<usize>,
    ) -> Self {
        let fse_state_mapping = fse_table.parse_state_table();

        Self {
            last_offset: initial_offset.unwrap_or_default(),
            base_line: 0,
            next_bits: fse_table.accuracy_log as usize,
            fse_state_mapping,
        }
    }

    /// parse for next symbol, also output the witness
    pub fn process<R: Read>(
        &mut self, 
        // notice the fse stream is read BACKWARD
        reader: &mut BitReader<R, BigEndian>,
        updated_offset: Option<usize>,
    ) -> Result<WitnessRow>{

        let value = reader.read::<u32>(self.next_bits as u32)?;
        let next_state = self.base_line + value;

        let fse_state = self.fse_state_mapping
            .get(&{next_state as u64})
            .expect("next state should be in fse table");

        let begin_offset = updated_offset.unwrap_or(self.last_offset);
        self.next_bits = fse_state.2 as usize;
        self.base_line = fse_state.1;
        let end_offset = begin_offset + self.next_bits;
        
        Ok((
            FseTableRow{
                state: next_state as u64,
                symbol: fse_state.0,
                baseline: fse_state.1 as u64,
                num_bits: fse_state.2 as u64,
            },
            begin_offset,
            end_offset,
        ))
    }


}
