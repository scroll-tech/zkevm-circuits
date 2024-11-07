use cfg_if::cfg_if;

// enum DataAvailability {
//     Eip4844,
//     Avail,
// }

mod blob_data;
use blob_data::{AssignedBlobDataExport, BlobDataConfig};

// TODO: remove dead code instead
#[allow(dead_code)]
mod avail;

// TODO: remove dead code instead
#[allow(dead_code)]
mod eip4844;

cfg_if! {
    if #[cfg(feature = "da-avail")] {
        // const DATA_AVAILABILITY: DataAvailability = DataAvailability::Avail;
        pub use avail::{BlobConsistencyConfig, BlobConsistencyWitness, BLOB_WIDTH, get_blob_bytes};
    } else {
        // const DATA_AVAILABILITY: DatayAvailability = DataAvailability::Eip4844;
        pub use eip4844::{BlobConsistencyConfig, BlobConsistencyWitness, BLOB_WIDTH, get_blob_bytes};
    }
}
