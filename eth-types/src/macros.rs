//! Collection of utility macros used within this crate.

macro_rules! impl_from_usize_wrappers {
    ($implemented:ty = $alias:expr, ($($implementor:ty),*)) => {
        $(impl From<$implementor> for $implemented {
            fn from(item: $implementor) -> $implemented {
                $alias(item as usize)
            }
        })*
    };
}

// ----------------------------------- //
//            Ops traits               //
// ----------------------------------- //

/// Define borrow and non-borrow variants of `Add`.
/// Requires the impl of Add<&RHS> for &LHS
macro_rules! define_add_variants {
    (LHS = $lhs:ty, RHS = $rhs:ty, Output = $out:ty) => {
        impl<'b> core::ops::Add<&'b $rhs> for $lhs {
            type Output = $out;
            fn add(self, rhs: &'b $rhs) -> $out {
                &self + rhs
            }
        }

        impl<'a> core::ops::Add<$rhs> for &'a $lhs {
            type Output = $out;
            fn add(self, rhs: $rhs) -> $out {
                self + &rhs
            }
        }

        impl core::ops::Add<$rhs> for $lhs {
            type Output = $out;
            fn add(self, rhs: $rhs) -> $out {
                &self + &rhs
            }
        }
    };
}

/// Define non-borrow variants of `AddAssign`.
macro_rules! define_add_assign_variants {
    (LHS = $lhs:ty, RHS = $rhs:ty) => {
        impl core::ops::AddAssign<$rhs> for $lhs {
            fn add_assign(&mut self, rhs: $rhs) {
                *self += &rhs;
            }
        }
    };
}

/// Define borrow and non-borrow variants of `Sub`.
macro_rules! define_sub_variants {
    (LHS = $lhs:ty, RHS = $rhs:ty, Output = $out:ty) => {
        impl<'b> core::ops::Sub<&'b $rhs> for $lhs {
            type Output = $out;
            fn sub(self, rhs: &'b $rhs) -> $out {
                &self - rhs
            }
        }

        impl<'a> core::ops::Sub<$rhs> for &'a $lhs {
            type Output = $out;
            fn sub(self, rhs: $rhs) -> $out {
                self - &rhs
            }
        }

        impl core::ops::Sub<$rhs> for $lhs {
            type Output = $out;
            fn sub(self, rhs: $rhs) -> $out {
                &self - &rhs
            }
        }
    };
}

/// Define non-borrow variants of `SubAssign`.
macro_rules! define_sub_assign_variants {
    (LHS = $lhs:ty, RHS = $rhs:ty) => {
        impl core::ops::SubAssign<$rhs> for $lhs {
            fn sub_assign(&mut self, rhs: $rhs) {
                *self -= &rhs;
            }
        }
    };
}

/// Define borrow and non-borrow variants of `Mul`.
macro_rules! define_mul_variants {
    (LHS = $lhs:ty, RHS = $rhs:ty, Output = $out:ty) => {
        impl<'b> core::ops::Mul<&'b $rhs> for $lhs {
            type Output = $out;
            fn mul(self, rhs: &'b $rhs) -> $out {
                &self * rhs
            }
        }

        impl<'a> core::ops::Mul<$rhs> for &'a $lhs {
            type Output = $out;
            fn mul(self, rhs: $rhs) -> $out {
                self * &rhs
            }
        }

        impl core::ops::Mul<$rhs> for $lhs {
            type Output = $out;
            fn mul(self, rhs: $rhs) -> $out {
                &self * &rhs
            }
        }
    };
}

/// Define non-borrow variants of `MulAssign`.
macro_rules! define_mul_assign_variants {
    (LHS = $lhs:ty, RHS = $rhs:ty) => {
        impl core::ops::MulAssign<$rhs> for $lhs {
            fn mul_assign(&mut self, rhs: $rhs) {
                *self *= &rhs;
            }
        }
    };
}

/// Define Range indexing ops for the given type converting the ranges
/// internally.
macro_rules! define_range_index_variants {
    (IN_RANGE = $inner_range:ty, OUT_RANGE = $out_range:ty, STRUCT_CONTAINER = $struc:ty, INDEX_OUTPUT = $output:ty) => {
        impl core::ops::Index<core::ops::Range<$out_range>> for $struc {
            type Output = $output;

            #[inline]
            fn index(&self, index: core::ops::Range<$out_range>) -> &Self::Output {
                &self.0[..][convert_range(index)]
            }
        }

        impl core::ops::Index<core::ops::RangeFull> for $struc {
            type Output = $output;

            #[inline]
            fn index(&self, _index: core::ops::RangeFull) -> &Self::Output {
                &self.0[..]
            }
        }

        impl core::ops::Index<core::ops::RangeTo<$out_range>> for $struc {
            type Output = $output;

            #[inline]
            fn index(&self, index: core::ops::RangeTo<$out_range>) -> &Self::Output {
                &self.0[..][convert_range_to(index)]
            }
        }

        impl core::ops::Index<core::ops::RangeFrom<$out_range>> for $struc {
            type Output = $output;

            #[inline]
            fn index(&self, index: core::ops::RangeFrom<$out_range>) -> &Self::Output {
                &self.0[..][convert_range_from(index)]
            }
        }

        impl core::ops::Index<core::ops::RangeToInclusive<$out_range>> for $struc {
            type Output = $output;

            #[inline]
            fn index(&self, index: core::ops::RangeToInclusive<$out_range>) -> &Self::Output {
                &self.0[..][convert_range_to_inclusive(index)]
            }
        }

        fn convert_range(range: core::ops::Range<$out_range>) -> core::ops::Range<$inner_range> {
            core::ops::Range {
                start: range.start.0,
                end: range.end.0,
            }
        }

        fn convert_range_from(
            range: core::ops::RangeFrom<$out_range>,
        ) -> core::ops::RangeFrom<$inner_range> {
            core::ops::RangeFrom {
                start: range.start.0,
            }
        }

        fn convert_range_to(
            range: core::ops::RangeTo<$out_range>,
        ) -> core::ops::RangeTo<$inner_range> {
            core::ops::RangeTo { end: range.end.0 }
        }

        fn convert_range_to_inclusive(
            range: core::ops::RangeToInclusive<$out_range>,
        ) -> core::ops::RangeToInclusive<$inner_range> {
            core::ops::RangeToInclusive { end: range.end.0 }
        }
    };
}

/// Triggers a signal that a feature is unimplemented, warns if
/// `warn-unimplemented` feature is set
#[cfg(feature = "warn-unimplemented")]
#[macro_export]
macro_rules! evm_unimplemented {
    ($($arg:tt)+) => {
        log::warn!("evm_unimplemented: {}", format_args!($($arg)+))
    };
}

/// Triggers a signal that a feature is unimplemented, panics if
/// `warn-unimplemented` feature is not set
#[cfg(not(feature = "warn-unimplemented"))]
#[macro_export]
macro_rules! evm_unimplemented {
    ($($arg:tt)+) => {
        (|| panic!("evm_unimplemented: {}",format_args!($($arg)+)))()
    };
}
