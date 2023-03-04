use crate::util::Expr;
use eth_types::Field;
use halo2_proofs::plonk::Expression;

mod abs_word;
mod add_words;
mod batched_is_zero;
mod binary_number;
mod byte_size;
mod cmp_words;
mod comparison;
mod constant_division;
mod is_equal;
mod is_zero;
mod lt;
mod lt_word;
mod min_max;
mod modulo;
mod mul_add_words;
mod mul_add_words512;
mod mul_word_u64;
mod pair_select;
mod range_check;
mod rlp;
#[cfg(test)]
mod test_util;

pub(crate) use abs_word::AbsWordGadget;
pub(crate) use add_words::AddWordsGadget;
#[allow(unused_imports)]
pub(crate) use batched_is_zero::BatchedIsZeroGadget;
#[allow(unused_imports)]
pub(crate) use binary_number::BinaryNumberGadget;
pub(crate) use byte_size::ByteSizeGadget;
pub(crate) use cmp_words::CmpWordsGadget;
pub(crate) use comparison::ComparisonGadget;
pub(crate) use constant_division::ConstantDivisionGadget;
pub(crate) use is_equal::IsEqualGadget;
pub(crate) use is_zero::IsZeroGadget;
pub(crate) use lt::LtGadget;
pub(crate) use lt_word::LtWordGadget;
pub(crate) use min_max::MinMaxGadget;
pub(crate) use modulo::ModGadget;
pub(crate) use mul_add_words::MulAddWordsGadget;
pub(crate) use mul_add_words512::MulAddWords512Gadget;
pub(crate) use mul_word_u64::MulWordByU64Gadget;
pub(crate) use pair_select::PairSelectGadget;
pub(crate) use range_check::RangeCheckGadget;
pub(crate) use rlp::ContractCreateGadget;

// This function generates a Lagrange polynomial in the range [start, end) which
// will be evaluated to 1 when `exp == value`, otherwise 0
pub(crate) fn generate_lagrange_base_polynomial<
    F: Field,
    Exp: Expr<F>,
    R: Iterator<Item = usize>,
>(
    exp: Exp,
    val: usize,
    range: R,
) -> Expression<F> {
    let mut numerator = 1u64.expr();
    let mut denominator = F::from(1);
    for x in range {
        if x != val {
            numerator = numerator * (exp.expr() - x.expr());
            denominator *= F::from(val as u64) - F::from(x as u64);
        }
    }
    numerator * denominator.invert().unwrap()
}
