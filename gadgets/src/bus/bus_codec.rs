use super::Field;
use crate::util::Expr;
use halo2_proofs::{circuit::Value, plonk::Expression};
use std::{cmp::Eq, hash::Hash, marker::PhantomData};

/// The default message type for expressions.
pub type DefaultMsgExpr<F> = Vec<Expression<F>>;

/// The default message type for values.
pub type DefaultMsgVal<F> = Vec<Value<F>>;

/// The codec for expressions.
pub type BusCodecExpr<F, M> = BusCodec<Expression<F>, M>;

/// The codec for values.
pub type BusCodecVal<F, M> = BusCodec<Value<F>, M>;

/// A message codec that adds a random value to the message.
#[derive(Clone, Debug)]
pub struct BusCodec<T, M> {
    rand: T,
    _marker: PhantomData<M>,
}

impl<T, M> BusCodec<T, M> {
    /// Create a new message codec.
    pub fn new(rand: T) -> Self {
        Self {
            rand,
            _marker: PhantomData,
        }
    }
}

impl<F, M> BusCodec<Expression<F>, M>
where
    F: Field,
    M: BusMessageExpr<F>,
{
    /// Compress a message into a field element, such that:
    /// - the map from message to elements is collision-resistant.
    /// - the inverses of the elements are linearly independent.
    /// - Elements are non-zero.
    pub fn compress(&self, msg: M) -> Expression<F> {
        msg.into_items()
            .fold(1.expr(), |acc, f| self.rand.clone() * acc + f)
    }
}

impl<F, M> BusCodec<Value<F>, M>
where
    F: Field,
    M: BusMessage<F>,
{
    /// Compress a message into a field element, such that:
    /// - the map from message to elements is collision-resistant.
    /// - the inverses of the elements are linearly independent.
    /// - Elements are non-zero.
    pub fn compress(&self, msg: M) -> Value<F> {
        self.rand
            .map(|rand| msg.into_items().fold(F::one(), |acc, f| rand * acc + f))
    }
}

/// A message as expressions to configure circuits.
pub trait BusMessageExpr<F>: BusMessage<Expression<F>> {}
impl<F, M> BusMessageExpr<F> for M where M: BusMessage<Expression<F>> {}

/// A message as values to be assigned.
pub trait BusMessageF<F>: BusMessage<F> + Eq + Hash {}
impl<F, M> BusMessageF<F> for M where M: BusMessage<F> + Eq + Hash {}

/// A trait for messages that can be encoded.
pub trait BusMessage<T>: Clone {
    /// The item iterator type.
    type IntoIter: Iterator<Item = T>;

    /// Convert the message into an iterator.
    fn into_items(self) -> Self::IntoIter;
}

// The default implementation of `BusMessage` for iterators of compatible types.
impl<T, I> BusMessage<T> for I
where
    I: IntoIterator + Clone,
    I::Item: Into<T>,
{
    type IntoIter = std::iter::Map<I::IntoIter, fn(I::Item) -> T>;

    fn into_items(self) -> Self::IntoIter {
        self.into_iter().map(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::halo2curves::bn256::Fr;

    #[derive(Clone, Debug, Hash)]
    struct TestMessage {
        a: u64,
        b: u64,
    }

    impl<T: From<u64>> BusMessage<T> for TestMessage {
        type IntoIter = std::array::IntoIter<T, 2>;

        fn into_items(self) -> Self::IntoIter {
            [self.a.into(), self.b.into()].into_iter()
        }
    }

    #[test]
    fn test_codec() {
        let rand = Value::known(Fr::from(10u64));
        {
            // Using vectors as message type.
            let codec = BusCodec::new(rand);
            let msg = vec![2u64, 3u64];
            let compressed = codec.compress(msg);

            assert!(!compressed.is_none());
            compressed.map(|c| assert_eq!(c, Fr::from(123)));
        }
        {
            // Using a custom message type.
            let codec = BusCodec::new(rand);
            let msg = TestMessage { a: 2, b: 3 };
            let compressed = codec.compress(msg);

            assert!(!compressed.is_none());
            compressed.map(|c| assert_eq!(c, Fr::from(123)));
        }
    }
}
