use core::mem::MaybeUninit;

use crate::{raw, Sha256Context, HASH_LEN};

#[derive(Default)]
pub struct Context {
    inner: raw::mbedtls_sha256_context,
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            raw::mbedtls_sha256_free(&mut self.inner);
        }
    }
}

impl Default for raw::mbedtls_sha256_context {
    fn default() -> Self {
        let mut context = MaybeUninit::uninit();
        unsafe {
            raw::mbedtls_sha256_init(context.as_mut_ptr());
            raw::mbedtls_sha256_starts(context.as_mut_ptr(), 0);
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
                raw::mbedtls_sha256_update(&mut self.inner, bytes.as_ptr(), bytes.len());
            };
        }
    }

    fn finalize(mut self) -> [u8; HASH_LEN] {
        let mut output: [u8; HASH_LEN] = Default::default();
        unsafe {
            raw::mbedtls_sha256_finish(&mut self.inner, output.as_mut_ptr());
        };
        output
    }
}
