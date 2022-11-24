use core::mem::MaybeUninit;

use crate::{raw, Sha256Context, HASH_LEN};

#[derive(Default)]
pub struct Context {
    inner: raw::secp256k1_sha256,
}

impl Default for raw::secp256k1_sha256 {
    fn default() -> Self {
        let mut context = MaybeUninit::uninit();
        unsafe {
            raw::secp256k1_sha256_initialize(context.as_mut_ptr());
            context.assume_init()
        }
    }
}

impl Sha256Context for Context {
    fn new() -> Self {
        Default::default()
    }

    fn update(&mut self, bytes: &[u8]) {
        if !bytes.is_empty() {
            unsafe {
                raw::secp256k1_sha256_write(&mut self.inner, bytes.as_ptr(), bytes.len());
            };
        }
    }

    fn finalize(mut self) -> [u8; HASH_LEN] {
        let mut output: [u8; HASH_LEN] = Default::default();
        unsafe {
            raw::secp256k1_sha256_finalize(&mut self.inner, output.as_mut_ptr());
        };
        output
    }
}
