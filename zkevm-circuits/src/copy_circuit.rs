//! The Copy circuit implements constraints and lookups for read-write steps for
//! copied bytes while execution opcodes such as CALLDATACOPY, CODECOPY, LOGS,
//! etc.

use bus_mapping::circuit_input_builder::{CopyDataType, CopyEvent, CopyStep, NumberOrHash};
use eth_types::{Field, ToAddress, ToScalar, U256};
use gadgets::{
    binary_number::BinaryNumberChip,
    less_than::{LtChip, LtConfig, LtInstruction},
    util::{and, not, or, Expr},
};
use halo2_proofs::{
    circuit::{Layouter, Region},
    plonk::{Advice, Column, ConstraintSystem, Error, Fixed, Selector},
    poly::Rotation,
};

use crate::{
    evm_circuit::{
        util::{constraint_builder::BaseConstraintBuilder, RandomLinearCombination},
        witness::Block,
    },
    table::{
        BytecodeFieldTag, CopyTable, LookupTable, RwTableTag, TxContextFieldTag, TxLogFieldTag,
    },
};

/// Encode the type `NumberOrHash` into a field element
pub fn number_or_hash_to_field<F: Field>(v: &NumberOrHash, randomness: F) -> F {
    match v {
        NumberOrHash::Number(n) => F::from(*n as u64),
        NumberOrHash::Hash(h) => {
            // since code hash in the bytecode table is represented in
            // the little-endian form, we reverse the big-endian bytes
            // of H256.
            let le_bytes = {
                let mut b = h.to_fixed_bytes();
                b.reverse();
                b
            };
            RandomLinearCombination::random_linear_combine(le_bytes, randomness)
        }
    }
}

/// The rw table shared between evm circuit and state circuit
#[derive(Clone, Copy, Debug)]
pub struct CopyCircuit<F> {
    /// Whether the row is enabled or not.
    pub q_enable: Column<Fixed>,
    /// Whether this row denotes a step. A read row is a step and a write row is
    /// not.
    pub q_step: Selector,
    /// Whether the row is the last read-write pair for a copy event.
    pub is_last: Column<Advice>,
    /// The Copy Table contains the columns that are exposed via the lookup
    /// expressions
    pub copy_table: CopyTable,
    /// The value copied in this copy step.
    pub value: Column<Advice>,
    /// In case of a bytecode tag, this denotes whether or not the copied byte
    /// is an opcode or push data byte.
    pub is_code: Column<Advice>,
    /// Whether the row is padding.
    pub is_pad: Column<Advice>,
    /// Lt chip to check: src_addr < src_addr_end.
    /// Since `src_addr` and `src_addr_end` are u64, 8 bytes are sufficient for
    /// the Lt chip.
    pub addr_lt_addr_end: LtConfig<F, 8>,
}

impl<F: Field> CopyCircuit<F> {
    /// Configure the Copy Circuit constraining read-write steps and doing
    /// appropriate lookups to the Tx Table, RW Table and Bytecode Table.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        tx_table: &dyn LookupTable<F>,
        rw_table: &dyn LookupTable<F>,
        bytecode_table: &dyn LookupTable<F>,
        copy_table: CopyTable,
        q_enable: Column<Fixed>,
    ) -> Self {
        let q_step = meta.complex_selector();
        let is_last = meta.advice_column();
        let value = meta.advice_column();
        let is_code = meta.advice_column();
        let is_pad = meta.advice_column();
        let is_first = copy_table.is_first;
        let id = copy_table.id;
        let addr = copy_table.addr;
        let src_addr_end = copy_table.src_addr_end;
        let bytes_left = copy_table.bytes_left;
        let rw_counter = copy_table.rw_counter;
        let rwc_inc_left = copy_table.rwc_inc_left;
        let tag = copy_table.tag;

        let addr_lt_addr_end = LtChip::configure(
            meta,
            |meta| meta.query_selector(q_step),
            |meta| meta.query_advice(addr, Rotation::cur()),
            |meta| meta.query_advice(src_addr_end, Rotation::cur()),
        );

        meta.create_gate("verify row", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_boolean(
                "is_first is boolean",
                meta.query_advice(is_first, Rotation::cur()),
            );
            cb.require_boolean(
                "is_last is boolean",
                meta.query_advice(is_last, Rotation::cur()),
            );
            cb.require_zero(
                "is_first == 0 when q_step == 0",
                and::expr([
                    not::expr(meta.query_selector(q_step)),
                    meta.query_advice(is_first, Rotation::cur()),
                ]),
            );
            cb.require_zero(
                "is_last == 0 when q_step == 1",
                and::expr([
                    meta.query_advice(is_last, Rotation::cur()),
                    meta.query_selector(q_step),
                ]),
            );

            let not_last_two_rows = 1.expr()
                - meta.query_advice(is_last, Rotation::cur())
                - meta.query_advice(is_last, Rotation::next());
            cb.condition(not_last_two_rows, |cb| {
                cb.require_equal(
                    "rows[0].id == rows[2].id",
                    meta.query_advice(id, Rotation::cur()),
                    meta.query_advice(id, Rotation(2)),
                );
                cb.require_equal(
                    "rows[0].tag == rows[2].tag",
                    tag.value(Rotation::cur())(meta),
                    tag.value(Rotation(2))(meta),
                );
                cb.require_equal(
                    "rows[0].addr + 1 == rows[2].addr",
                    meta.query_advice(addr, Rotation::cur()) + 1.expr(),
                    meta.query_advice(addr, Rotation(2)),
                );
                cb.require_equal(
                    "rows[0].src_addr_end == rows[2].src_addr_end for non-last step",
                    meta.query_advice(src_addr_end, Rotation::cur()),
                    meta.query_advice(src_addr_end, Rotation(2)),
                );
            });

            let rw_diff = and::expr([
                or::expr([
                    tag.value_equals(CopyDataType::Memory, Rotation::cur())(meta),
                    tag.value_equals(CopyDataType::TxLog, Rotation::cur())(meta),
                ]),
                not::expr(meta.query_advice(is_pad, Rotation::cur())),
            ]);
            cb.condition(
                not::expr(meta.query_advice(is_last, Rotation::cur())),
                |cb| {
                    cb.require_equal(
                        "rows[0].rw_counter + rw_diff == rows[1].rw_counter",
                        meta.query_advice(rw_counter, Rotation::cur()) + rw_diff.clone(),
                        meta.query_advice(rw_counter, Rotation::next()),
                    );
                    cb.require_equal(
                        "rows[0].rwc_inc_left - rw_diff == rows[1].rwc_inc_left",
                        meta.query_advice(rwc_inc_left, Rotation::cur()) - rw_diff.clone(),
                        meta.query_advice(rwc_inc_left, Rotation::next()),
                    );
                },
            );
            cb.condition(meta.query_advice(is_last, Rotation::cur()), |cb| {
                cb.require_equal(
                    "rwc_inc_left == rw_diff for last row in the copy slot",
                    meta.query_advice(rwc_inc_left, Rotation::cur()),
                    rw_diff,
                );
            });

            cb.gate(meta.query_fixed(q_enable, Rotation::cur()))
        });

        meta.create_gate("verify step", |meta| {
            let mut cb = BaseConstraintBuilder::default();

            cb.require_zero(
                "bytes_left == 1 for last step",
                and::expr([
                    meta.query_advice(is_last, Rotation::next()),
                    1.expr() - meta.query_advice(bytes_left, Rotation::cur()),
                ]),
            );
            cb.condition(
                not::expr(meta.query_advice(is_last, Rotation::next())),
                |cb| {
                    cb.require_equal(
                        "bytes_left == bytes_left_next + 1 for non-last step",
                        meta.query_advice(bytes_left, Rotation::cur()),
                        meta.query_advice(bytes_left, Rotation(2)) + 1.expr(),
                    );
                },
            );
            cb.require_equal(
                "write value == read value",
                meta.query_advice(value, Rotation::cur()),
                meta.query_advice(value, Rotation::next()),
            );
            cb.require_zero(
                "value == 0 when is_pad == 1 for read",
                and::expr([
                    meta.query_advice(is_pad, Rotation::cur()),
                    meta.query_advice(value, Rotation::cur()),
                ]),
            );
            cb.require_equal(
                "is_pad == 1 - (src_addr < src_addr_end) for read row",
                1.expr() - addr_lt_addr_end.is_lt(meta, None),
                meta.query_advice(is_pad, Rotation::cur()),
            );
            cb.require_zero(
                "is_pad == 0 for write row",
                meta.query_advice(is_pad, Rotation::next()),
            );

            cb.gate(meta.query_selector(q_step))
        });

        meta.lookup_any("Memory lookup", |meta| {
            let cond = meta.query_fixed(q_enable, Rotation::cur())
                * tag.value_equals(CopyDataType::Memory, Rotation::cur())(meta)
                * not::expr(meta.query_advice(is_pad, Rotation::cur()));
            vec![
                meta.query_advice(rw_counter, Rotation::cur()),
                not::expr(meta.query_selector(q_step)),
                RwTableTag::Memory.expr(),
                meta.query_advice(id, Rotation::cur()), // call_id
                meta.query_advice(addr, Rotation::cur()), // memory address
                0.expr(),
                0.expr(),
                meta.query_advice(value, Rotation::cur()),
                0.expr(),
                0.expr(),
                0.expr(),
            ]
            .into_iter()
            .zip(rw_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (cond.clone() * arg, table))
            .collect()
        });

        meta.lookup_any("TxLog lookup", |meta| {
            let cond = meta.query_fixed(q_enable, Rotation::cur())
                * tag.value_equals(CopyDataType::TxLog, Rotation::cur())(meta);
            vec![
                meta.query_advice(rw_counter, Rotation::cur()),
                1.expr(),
                RwTableTag::TxLog.expr(),
                meta.query_advice(id, Rotation::cur()), // tx_id
                meta.query_advice(addr, Rotation::cur()), // byte_index || field_tag || log_id
                0.expr(),
                0.expr(),
                meta.query_advice(value, Rotation::cur()),
                0.expr(),
                0.expr(),
                0.expr(),
            ]
            .into_iter()
            .zip(rw_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (cond.clone() * arg, table))
            .collect()
        });

        meta.lookup_any("Bytecode lookup", |meta| {
            let cond = meta.query_fixed(q_enable, Rotation::cur())
                * tag.value_equals(CopyDataType::Bytecode, Rotation::cur())(meta)
                * not::expr(meta.query_advice(is_pad, Rotation::cur()));
            vec![
                meta.query_advice(id, Rotation::cur()),
                BytecodeFieldTag::Byte.expr(),
                meta.query_advice(addr, Rotation::cur()),
                meta.query_advice(is_code, Rotation::cur()),
                meta.query_advice(value, Rotation::cur()),
            ]
            .into_iter()
            .zip(bytecode_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (cond.clone() * arg, table))
            .collect()
        });

        meta.lookup_any("Tx calldata lookup", |meta| {
            let cond = meta.query_fixed(q_enable, Rotation::cur())
                * tag.value_equals(CopyDataType::TxCalldata, Rotation::cur())(meta)
                * not::expr(meta.query_advice(is_pad, Rotation::cur()));
            vec![
                meta.query_advice(id, Rotation::cur()),
                TxContextFieldTag::CallData.expr(),
                meta.query_advice(addr, Rotation::cur()),
                meta.query_advice(value, Rotation::cur()),
            ]
            .into_iter()
            .zip(tx_table.table_exprs(meta).into_iter())
            .map(|(arg, table)| (cond.clone() * arg, table))
            .collect()
        });

        Self {
            q_enable,
            q_step,
            is_last,
            value,
            is_code,
            is_pad,
            addr_lt_addr_end,
            copy_table,
        }
    }

    /// Assign a witness block to the Copy Circuit.
    pub fn assign_block(
        &self,
        layouter: &mut impl Layouter<F>,
        block: &Block<F>,
    ) -> Result<(), Error> {
        let tag_chip = BinaryNumberChip::construct(self.copy_table.tag);
        let lt_chip = LtChip::construct(self.addr_lt_addr_end);

        layouter.assign_region(
            || "assign copy table",
            |mut region| {
                let mut offset = 0;
                for copy_event in block.copy_events.values() {
                    for (step_idx, copy_step) in copy_event.steps.iter().enumerate() {
                        self.assign_step(
                            &mut region,
                            offset,
                            block.randomness,
                            copy_event,
                            step_idx,
                            copy_step,
                            &tag_chip,
                            &lt_chip,
                        )?;
                        offset += 1;
                    }
                }
                // pad two rows in the end to satisfy Halo2 cell assignment check
                for _ in 0..2 {
                    self.assign_padding_row(&mut region, offset, &tag_chip)?;
                    offset += 1;
                }
                Ok(())
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn assign_step(
        &self,
        region: &mut Region<F>,
        offset: usize,
        randomness: F,
        copy_event: &CopyEvent,
        step_idx: usize,
        copy_step: &CopyStep,
        tag_chip: &BinaryNumberChip<F, CopyDataType, 3>,
        lt_chip: &LtChip<F, 8>,
    ) -> Result<(), Error> {
        // q_enable
        region.assign_fixed(|| "q_enable", self.q_enable, offset, || Ok(F::one()))?;
        // enable q_step on the Read step
        if copy_step.rw.is_read() {
            self.q_step.enable(region, offset)?;
        }

        let id = if copy_step.rw.is_read() {
            &copy_event.src_id
        } else {
            &copy_event.dst_id
        };
        let bytes_left = copy_event.length - step_idx as u64 / 2;

        // is_first
        region.assign_advice(
            || format!("assign is_first {}", offset),
            self.copy_table.is_first,
            offset,
            || Ok(if step_idx == 0 { F::one() } else { F::zero() }),
        )?;
        // is_last
        region.assign_advice(
            || format!("assign is_last {}", offset),
            self.is_last,
            offset,
            || {
                Ok(if step_idx == copy_event.steps.len() - 1 {
                    F::one()
                } else {
                    F::zero()
                })
            },
        )?;
        // id
        region.assign_advice(
            || format!("assign id {}", offset),
            self.copy_table.id,
            offset,
            || Ok(number_or_hash_to_field(id, randomness)),
        )?;
        // addr
        region.assign_advice(
            || format!("assign addr {}", offset),
            self.copy_table.addr,
            offset,
            || {
                Ok(match copy_step.tag {
                    CopyDataType::TxLog => {
                        let addr = (U256::from(copy_step.addr)
                            + (U256::from(TxLogFieldTag::Data as u64) << 32)
                            + (U256::from(copy_event.log_id.unwrap()) << 48))
                            .to_address();
                        addr.to_scalar().unwrap()
                    }
                    _ => F::from(copy_step.addr),
                })
            },
        )?;
        // value
        region.assign_advice(
            || format!("assign value {}", offset),
            self.value,
            offset,
            || Ok(F::from(copy_step.value as u64)),
        )?;
        // is_code
        region.assign_advice(
            || format!("assign is_code {}", offset),
            self.is_code,
            offset,
            || Ok(copy_step.is_code.map_or(F::zero(), |v| F::from(v))),
        )?;
        // is_pad
        region.assign_advice(
            || format!("assign is_pad {}", offset),
            self.is_pad,
            offset,
            || Ok(F::from(copy_step.is_pad)),
        )?;
        // rw_counter
        region.assign_advice(
            || format!("assign rw_counter {}", offset),
            self.copy_table.rw_counter,
            offset,
            || Ok(F::from(copy_step.rwc.0 as u64)),
        )?;
        // rwc_inc_left
        region.assign_advice(
            || format!("assign rwc_inc_left {}", offset),
            self.copy_table.rwc_inc_left,
            offset,
            || Ok(F::from(copy_step.rwc_inc_left)),
        )?;
        // tag binary number chip
        tag_chip.assign(region, offset, &copy_step.tag)?;
        // assignment for read steps
        if copy_step.rw.is_read() {
            // src_addr_end
            region.assign_advice(
                || format!("assign src_addr_end {}", offset),
                self.copy_table.src_addr_end,
                offset,
                || Ok(F::from(copy_event.src_addr_end)),
            )?;
            // bytes_left
            region.assign_advice(
                || format!("assign bytes_left {}", offset),
                self.copy_table.bytes_left,
                offset,
                || Ok(F::from(bytes_left)),
            )?;
            // lt chip
            lt_chip.assign(
                region,
                offset,
                F::from(copy_step.addr),
                F::from(copy_event.src_addr_end),
            )?;
        }
        Ok(())
    }

    fn assign_padding_row(
        &self,
        region: &mut Region<F>,
        offset: usize,
        tag_chip: &BinaryNumberChip<F, CopyDataType, 3>,
    ) -> Result<(), Error> {
        // q_enable
        region.assign_fixed(|| "q_enable", self.q_enable, offset, || Ok(F::zero()))?;
        // is_first
        region.assign_advice(
            || format!("assign is_first {}", offset),
            self.copy_table.is_first,
            offset,
            || Ok(F::zero()),
        )?;
        // is_last
        region.assign_advice(
            || format!("assign is_last {}", offset),
            self.is_last,
            offset,
            || Ok(F::zero()),
        )?;
        // id
        region.assign_advice(
            || format!("assign id {}", offset),
            self.copy_table.id,
            offset,
            || Ok(F::zero()),
        )?;
        // addr
        region.assign_advice(
            || format!("assign addr {}", offset),
            self.copy_table.addr,
            offset,
            || Ok(F::zero()),
        )?;
        // src_addr_end
        region.assign_advice(
            || format!("assign src_addr_end {}", offset),
            self.copy_table.src_addr_end,
            offset,
            || Ok(F::zero()),
        )?;
        // bytes_left
        region.assign_advice(
            || format!("assign bytes_left {}", offset),
            self.copy_table.bytes_left,
            offset,
            || Ok(F::zero()),
        )?;
        // value
        region.assign_advice(
            || format!("assign value {}", offset),
            self.value,
            offset,
            || Ok(F::zero()),
        )?;
        // is_code
        region.assign_advice(
            || format!("assign is_code {}", offset),
            self.is_code,
            offset,
            || Ok(F::zero()),
        )?;
        // is_pad
        region.assign_advice(
            || format!("assign is_pad {}", offset),
            self.is_pad,
            offset,
            || Ok(F::zero()),
        )?;
        // rw_counter
        region.assign_advice(
            || format!("assign rw_counter {}", offset),
            self.copy_table.rw_counter,
            offset,
            || Ok(F::zero()),
        )?;
        // rwc_inc_left
        region.assign_advice(
            || format!("assign rwc_inc_left {}", offset),
            self.copy_table.rwc_inc_left,
            offset,
            || Ok(F::zero()),
        )?;
        // tag
        tag_chip.assign(region, offset, &CopyDataType::default())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bus_mapping::{
        circuit_input_builder::{CircuitInputBuilder, CopyDataType},
        mock::BlockData,
        operation::RWCounter,
    };
    use eth_types::{bytecode, geth_types::GethData, Field, Word};
    use halo2_proofs::{
        circuit::{Layouter, SimpleFloorPlanner},
        dev::{MockProver, VerifyFailure},
        plonk::{Circuit, ConstraintSystem},
    };
    use mock::TestContext;
    use rand::{prelude::SliceRandom, Rng};

    use crate::{
        evm_circuit::witness::{block_convert, Block},
        table::{BytecodeTable, RwTable, TxTable},
    };

    #[derive(Clone)]
    struct MyConfig<F> {
        tx_table: TxTable,
        rw_table: RwTable,
        bytecode_table: BytecodeTable,
        copy_table: CopyCircuit<F>,
    }

    #[derive(Default)]
    struct MyCircuit<F> {
        block: Block<F>,
    }

    impl<F> MyCircuit<F> {
        pub fn new(block: Block<F>) -> Self {
            Self { block }
        }
    }

    impl<F: Field> Circuit<F> for MyCircuit<F> {
        type Config = MyConfig<F>;
        type FloorPlanner = SimpleFloorPlanner;

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let tx_table = TxTable::construct(meta);
            let rw_table = RwTable::construct(meta);
            let bytecode_table = BytecodeTable::construct(meta);
            let q_enable = meta.fixed_column();
            let copy_table = CopyTable::construct(meta, q_enable);
            let copy_table = CopyCircuit::configure(
                meta,
                &tx_table,
                &rw_table,
                &bytecode_table,
                copy_table,
                q_enable,
            );

            MyConfig {
                tx_table,
                rw_table,
                bytecode_table,
                copy_table,
            }
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), halo2_proofs::plonk::Error> {
            config
                .tx_table
                .load(&mut layouter, &self.block.txs, self.block.randomness)?;
            config.rw_table.load(
                &mut layouter,
                &self.block.rws,
                self.block.randomness,
                self.block.state_circuit_pad_to,
            )?;
            config.bytecode_table.load(
                &mut layouter,
                self.block.bytecodes.values(),
                self.block.randomness,
            )?;
            config.copy_table.assign_block(&mut layouter, &self.block)
        }
    }

    fn run_circuit<F: Field>(k: u32, block: Block<F>) -> Result<(), Vec<VerifyFailure>> {
        let circuit = MyCircuit::<F>::new(block);
        let prover = MockProver::<F>::run(k, &circuit, vec![]).unwrap();
        prover.verify()
    }

    fn gen_calldatacopy_data() -> CircuitInputBuilder {
        let code = bytecode! {
            PUSH32(Word::from(0x20))
            PUSH32(Word::from(0x00))
            PUSH32(Word::from(0x00))
            CALLDATACOPY
            STOP
        };
        let test_ctx = TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap();
        let block: GethData = test_ctx.into();
        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
        builder
    }

    fn gen_codecopy_data() -> CircuitInputBuilder {
        let code = bytecode! {
            PUSH32(Word::from(0x20))
            PUSH32(Word::from(0x00))
            PUSH32(Word::from(0x00))
            CODECOPY
            STOP
        };
        let test_ctx = TestContext::<2, 1>::simple_ctx_with_bytecode(code).unwrap();
        let block: GethData = test_ctx.into();
        let mut builder = BlockData::new_from_geth_data(block.clone()).new_circuit_input_builder();
        builder
            .handle_block(&block.eth_block, &block.geth_traces)
            .unwrap();
        builder
    }

    #[test]
    fn copy_circuit_valid_calldatacopy() {
        let builder = gen_calldatacopy_data();
        let block = block_convert(&builder.block, &builder.code_db);
        assert!(run_circuit(10, block).is_ok());
    }

    #[test]
    fn copy_circuit_valid_codecopy() {
        let builder = gen_codecopy_data();
        let block = block_convert(&builder.block, &builder.code_db);
        assert!(run_circuit(10, block).is_ok());
    }

    fn perturb_tag(block: &mut bus_mapping::circuit_input_builder::Block, tag: CopyDataType) {
        debug_assert!(!block.copy_events.is_empty());
        debug_assert!(!block.copy_events[0].steps.is_empty());

        let mut rng = rand::thread_rng();
        let idxs = block.copy_events[0]
            .steps
            .iter()
            .enumerate()
            .filter(|(_i, step)| step.tag == tag)
            .map(|(i, _step)| i)
            .collect::<Vec<usize>>();
        let rand_idx = idxs.choose(&mut rng).unwrap();
        match rng.gen::<f32>() {
            f if f < 0.25 => block.copy_events[0].steps[*rand_idx].addr = rng.gen(),
            f if f < 0.5 => block.copy_events[0].steps[*rand_idx].value = rng.gen(),
            f if f < 0.75 => block.copy_events[0].steps[*rand_idx].rwc = RWCounter(rng.gen()),
            _ => block.copy_events[0].steps[*rand_idx].rwc_inc_left = rng.gen(),
        }
    }

    #[test]
    fn copy_circuit_invalid_calldatacopy() {
        let mut builder = gen_calldatacopy_data();
        match rand::thread_rng().gen_bool(0.5) {
            true => perturb_tag(&mut builder.block, CopyDataType::Memory),
            false => perturb_tag(&mut builder.block, CopyDataType::TxCalldata),
        }
        let block = block_convert(&builder.block, &builder.code_db);
        assert!(run_circuit(10, block).is_err());
    }

    #[test]
    fn copy_circuit_invalid_codecopy() {
        let mut builder = gen_codecopy_data();
        match rand::thread_rng().gen_bool(0.5) {
            true => perturb_tag(&mut builder.block, CopyDataType::Memory),
            false => perturb_tag(&mut builder.block, CopyDataType::Bytecode),
        }
        let block = block_convert(&builder.block, &builder.code_db);
        assert!(run_circuit(10, block).is_err());
    }
}
