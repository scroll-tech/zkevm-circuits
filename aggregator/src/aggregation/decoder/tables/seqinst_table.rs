use eth_types::Field;
use gadgets::{
    comparator::{ComparatorChip, ComparatorConfig},
    is_equal::{IsEqualChip, IsEqualConfig},
    util::{and, not, Expr},
};


/// Table used carry the raw sequence instructions parsed from sequence section
/// and would be later transformed as the back-reference instructions
///
/// | Blk index |  Seq ind. |   Tag  |  Value | 
/// |-----------|-----------|--------|--------|
/// |     1     |    0      |  COUNT |   30   |
/// |     1     |    0      | LITERAL|   4    |
/// |     1     |    0      | OFFSET |   2    |
/// |     1     |    0      |  MATCH |   4    |
/// |     1     |    1      | LITERAL|   2    |
/// |     1     |    1      | OFFSET |   10   |
/// |     1     |    1      |  MATCH |   5    |
/// |    ...    |   ...     |   ...  |  ...   |
/// |     1     |    30     |  MATCH |   6    |
/// 
/// Above is a representation of this table. The Tag has following types:
/// - COUNT: indicate the count of sequence in current block
/// - LITERAL, OFFSET, MATCH: indicate the `Value` represent the parsed
///   value of `literal_len`, `offset` and `match_len`
/// 
/// The LITERAL, OFFSET, MATCH tag for the same sequence index MUST be
/// put in the continuous rows and in the same sequence as mentioned above
/// 
/// For block index we should use an 1-index so the empty
/// row can be safely as the default row for lookup
/// 
#[derive(Clone, Debug)]
pub struct SeqValueTable<F> {
    /// Fixed column to denote whether the constraints will be enabled or not.
    pub q_enabled: Column<Fixed>,
    /// The block's 1-indexed
    pub block_index: Column<Advice>,
    /// The sequence index for each tag, for COUNT tag it must be 0
    pub sequence_index: Column<Advice>,
    /// The tag for each value, 0 MUST be a non-tagged row and the
    /// value in this row would be omitted
    pub tag: Column<Advice>,
    /// The value of each entry in parsed sequence
    pub value: Column<Advice>,
}