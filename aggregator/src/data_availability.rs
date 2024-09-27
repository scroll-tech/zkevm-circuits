use cfg_if::cfg_if;

enum DataAvailibility {
    Eip4844,
    Avail,
}

cfg_if! {
    if #[cfg(feature = "da-4844")] {
        const DATA_AVAILABILITY: DataAvailibility = DataAvailibility::Eip4844;
    } else if #[cfg(feature = "da-avail")] {
        const DATA_AVAILABILITY: DataAvailibility = DataAvailibility::Avail;
    } else {
        unimplemented!("no da feature flag set");
    }
}

#[cfg(feature = "da-4844")]
mod eip4844;
#[cfg(feature = "da-avail")]
mod avail;