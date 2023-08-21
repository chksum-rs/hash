use anyhow::Result;
#[cfg(feature = "unstable")]
use chksum_build::{setup, BuildScript};

#[cfg(feature = "unstable")]
fn main() -> Result<()> {
    setup(&BuildScript)
}

#[cfg(not(feature = "unstable"))]
fn main() -> Result<()> {
    Ok(())
}
