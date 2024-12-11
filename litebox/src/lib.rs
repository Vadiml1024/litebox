//! # LiteBox
//!
//! > A security-focused library OS.
//!
//! LiteBox exposes a [`nix`](https://docs.rs/nix)/[`rustix`](https://docs.rs/rustix)-like interface
//! "above" when it is provided a `Platform` interface "below".
//!
//! To use LiteBox, you must provide a type that implements the [`platform::Provider`] trait; then,
//! one obtains a Rust-friendly POSIX-like interface (i.e., "nix-like" interface) via the rest of
//! the modules in this crate.

#![no_std]

extern crate alloc;

/// The underlying platform upon which LiteBox resides.
pub mod platform {
    use either::Either;

    /// A provider of a platform upon which LiteBox can execute.
    pub trait Provider {
        /// Punch through any functionality that is not explicitly part of the common shared
        /// platform interface. See [`Punchthrough`] for details.
        type Punchthrough: Punchthrough;
    }

    /// Punchthrough support allowing access to functionality not captured by [`Provider`].
    ///
    /// Ideally, this is implemented by a (possibly `#[non_exhaustive]`) enum where a platform
    /// provider can mark any unsupported/unimplemented punchthrough functionality with a
    /// [`PunchthroughError::Unsupported`] or [`PunchthroughError::Unimplemented`].
    pub trait Punchthrough {
        type ReturnSuccess;
        type ReturnFailure: core::error::Error;
        fn execute(self) -> Result<Self::ReturnSuccess, PunchthroughError<Self::ReturnFailure>>;
    }

    /// Possible errors for a [`Punchthrough`]
    #[derive(thiserror::Error, Debug)]
    pub enum PunchthroughError<E: core::error::Error> {
        #[error("attempted to execute unsupported punchthrough")]
        Unsupported,
        #[error("punchthrough for `{0}` is not implemented")]
        Unimplemented(&'static str),
        #[error(transparent)]
        Failure(#[from] E),
    }

    /// An error-implementing [`Either`]-style type.
    #[derive(thiserror::Error, Debug)]
    pub enum EitherError<L: core::error::Error, R: core::error::Error> {
        #[error(transparent)]
        Left(L),
        #[error(transparent)]
        Right(R),
    }

    // To support easily composing punchthroughs, it is implemented on the `Either` type on
    // punchthroughs. An implementation of punchthrough could follow a similar implementation to
    // obtain easy internal composability, but composing across crates providing punchthroughs is
    // likely best provided using this `Either` based composition.
    impl<L, R> Punchthrough for Either<L, R>
    where
        L: Punchthrough,
        R: Punchthrough,
    {
        type ReturnSuccess = Either<L::ReturnSuccess, R::ReturnSuccess>;
        type ReturnFailure = EitherError<L::ReturnFailure, R::ReturnFailure>;

        fn execute(self) -> Result<Self::ReturnSuccess, PunchthroughError<Self::ReturnFailure>> {
            match self {
                Either::Left(l) => match l.execute() {
                    Ok(res) => Ok(Either::Left(res)),
                    Err(PunchthroughError::Unsupported) => Err(PunchthroughError::Unsupported),
                    Err(PunchthroughError::Unimplemented(e)) => {
                        Err(PunchthroughError::Unimplemented(e))
                    }
                    Err(PunchthroughError::Failure(e)) => {
                        Err(PunchthroughError::Failure(EitherError::Left(e)))
                    }
                },
                Either::Right(r) => match r.execute() {
                    Ok(res) => Ok(Either::Right(res)),
                    Err(PunchthroughError::Unsupported) => Err(PunchthroughError::Unsupported),
                    Err(PunchthroughError::Unimplemented(e)) => {
                        Err(PunchthroughError::Unimplemented(e))
                    }
                    Err(PunchthroughError::Failure(e)) => {
                        Err(PunchthroughError::Failure(EitherError::Right(e)))
                    }
                },
            }
        }
    }
}

/// File-system related functionality
pub mod fs {}

/// Network-related functionality
pub mod net {}
