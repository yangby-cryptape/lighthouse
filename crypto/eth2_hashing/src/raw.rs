#![doc(hidden)]
#![allow(warnings)]
#![allow(missing_docs)]
#![allow(clippy::all)]

#[cfg(feature = "dynamic_bindgen")]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(all(not(feature = "dynamic_bindgen"), feature = "c_bitcoin_impl"))]
include!("generated/bitcoin.rs");

#[cfg(all(not(feature = "dynamic_bindgen"), feature = "c_mbedtls_impl"))]
include!("generated/mbedtls.rs");
