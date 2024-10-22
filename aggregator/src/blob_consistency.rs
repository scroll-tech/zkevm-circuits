use cfg_if::cfg_if;

// enum DataAvailability {
//     Eip4844,
//     Avail,
// }

mod blob_data;
use blob_data::{AssignedBlobDataExport, BlobDataConfig};

#[cfg(feature = "da-avail")]
mod avail;

#[cfg(not(feature = "da-avail"))]
mod eip4844;

cfg_if! {
    if #[cfg(feature = "da-avail")] {
        // const DATA_AVAILABILITY: DataAvailability = DataAvailability::Avail;
        pub use avail::{BlobConsistencyConfig, BlobConsistencyWitness, BLOB_WIDTH};
    } else {
        // const DATA_AVAILABILITY: DatayAvailability = DataAvailability::Eip4844;
        pub use eip4844::{BlobConsistencyConfig, BlobConsistencyWitness, BLOB_WIDTH};
    }
}
