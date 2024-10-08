use cfg_if::cfg_if;

enum DataAvailibility {
    Eip4844,
    Avail,
}

mod blob_data;
use blob_data::{AssignedBlobDataExport, BlobDataConfig};

#[cfg(feature = "da-avail")]
mod avail;

#[cfg(feature = "da-eip4844")]
mod eip4844;

cfg_if! {
    if #[cfg(feature = "da-avail")] {
        const DATA_AVAILABILITY: DataAvailibility = DataAvailibility::Avail;
        pub use avail::{get_coefficients, BlobConsistencyConfig, BlobConsistencyWitness, BLOB_WIDTH};
    } else if #[cfg(feature = "da-eip4844")] {
        const DATA_AVAILABILITY: DataAvailibility = DataAvailibility::Eip4844;
        pub use eip4844::{get_coefficients, BlobConsistencyConfig, BlobConsistencyWitness, BLOB_WIDTH};
    } else {
        compile_error!("no da feature flag set");
    }
}
