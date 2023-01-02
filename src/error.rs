use std::num::ParseIntError;
use std::result;

/// A common error type for the current crate.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    #[cfg_attr(docsrs, doc(hidden))]
    #[error("Invalid length `{value}`, proper value `{proper}`")]
    InvalidLength { value: usize, proper: usize },
    #[cfg_attr(docsrs, doc(hidden))]
    #[error(transparent)]
    ParseError(#[from] ParseIntError),
}

/// Type alias for [`Result`](std::result::Result) with an error type of [`Error`].
pub type Result<T> = result::Result<T, Error>;
