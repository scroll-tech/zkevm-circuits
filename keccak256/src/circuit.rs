pub mod word_builder;

pub const MAX_INPUT_BYTES: usize = MAX_INPUT_WORDS * BYTES_PER_WORD;
pub const MAX_INPUT_WORDS: usize = MAX_PERM_ROUNDS * NEXT_INPUTS_WORDS;
pub const BYTES_PER_WORD: usize = 8;
pub const NEXT_INPUTS_WORDS: usize = 17;
pub const MAX_PERM_ROUNDS: usize = 10;
