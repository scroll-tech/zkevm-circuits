use halo2_proofs::{arithmetic::FieldExt, circuit::Value};

use crate::{
    util::Challenges,
    witness::tx::{SignedTxEip2930, TxEip2930},
};

use super::{RlpFsmWitnessGen, RomTableRow};

impl<F: FieldExt> RlpFsmWitnessGen<F> for TxEip2930 {
    fn gen_sm_witness(&self, challenges: &Challenges<Value<F>>) -> Vec<super::RlpFsmWitnessRow<F>> {
        unimplemented!()
    }

    fn gen_data_table(&self, challenges: &Challenges<Value<F>>) -> Vec<super::DataTable<F>> {
        unimplemented!()
    }
}

impl<F: FieldExt> RlpFsmWitnessGen<F> for SignedTxEip2930 {
    fn gen_sm_witness(&self, challenges: &Challenges<Value<F>>) -> Vec<super::RlpFsmWitnessRow<F>> {
        unimplemented!()
    }

    fn gen_data_table(&self, challenges: &Challenges<Value<F>>) -> Vec<super::DataTable<F>> {
        unimplemented!()
    }
}

pub fn tx_sign_rom_table_rows<F: FieldExt>() -> Vec<RomTableRow<F>> {
    unimplemented!()
}

pub fn tx_hash_rom_table_rows<F: FieldExt>() -> Vec<RomTableRow<F>> {
    unimplemented!()
}
