use halo2_proofs::{circuit::Value, halo2curves::bn256::Fr};

use crate::aggregation::decoder::witgen::util::bit_length;

use super::{FixedLookupTag, FixedLookupValues};

#[derive(Clone, Debug)]
pub struct RomVariableBitPacking {
    pub range: u64,
    pub value_read: u64,
    pub value_decoded: u64,
    pub num_bits: u64,
}

impl FixedLookupValues for RomVariableBitPacking {
    fn values() -> Vec<[Value<Fr>; 7]> {
        // The maximum range R we ever have is 512 (1 << 9) as the maximum possible accuracy log is
        // 9. So we only need to support a range up to R + 1, i.e. 513.
        let rows = (1..=513)
            .flat_map(|range| {
                // Get the number of bits required to represent the highest number in this range.
                let size = bit_length(range) as u32;
                let max = 1 << size;

                // Whether ``range`` is a power of 2 minus 1, i.e. 2^k - 1. In these cases, we
                // don't need variable bit-packing as all values in the range can be represented by
                // the same number of bits.
                let is_no_var = range & (range + 1) == 0;

                // The value read is in fact the value decoded.
                if is_no_var {
                    return (0..=range)
                        .map(|value_read| RomVariableBitPacking {
                            range,
                            value_read,
                            value_decoded: value_read,
                            num_bits: size as u64,
                        })
                        .collect::<Vec<_>>();
                }

                let n_total = range + 1;
                let lo_pin = max - n_total;
                let n_remaining = n_total - lo_pin;
                let hi_pin_1 = lo_pin + (n_remaining / 2);
                let hi_pin_2 = max - (n_remaining / 2);

                (0..max)
                    .map(|value_read| {
                        // the value denoted by the low (size - 1)-bits.
                        let lo_value = value_read & ((1 << (size - 1)) - 1);
                        let (num_bits, value_decoded) = if (0..lo_pin).contains(&lo_value) {
                            (size - 1, lo_value)
                        } else if (lo_pin..hi_pin_1).contains(&value_read) {
                            (size, value_read)
                        } else if (hi_pin_1..hi_pin_2).contains(&value_read) {
                            (size - 1, value_read - hi_pin_1)
                        } else {
                            assert!((hi_pin_2..max).contains(&value_read));
                            (size, value_read - lo_pin)
                        };
                        RomVariableBitPacking {
                            range,
                            value_read,
                            value_decoded,
                            num_bits: num_bits.into(),
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        rows.iter()
            .map(|row| {
                [
                    Value::known(Fr::from(FixedLookupTag::VariableBitPacking as u64)),
                    Value::known(Fr::from(row.range)),
                    Value::known(Fr::from(row.value_read)),
                    Value::known(Fr::from(row.value_decoded)),
                    Value::known(Fr::from(row.num_bits)),
                    Value::known(Fr::zero()),
                    Value::known(Fr::zero()),
                ]
            })
            .collect()
    }
}
