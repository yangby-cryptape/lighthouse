use sha2::{Digest as _, Sha256};

use crate::{Sha256Context, HASH_LEN};

pub(crate) struct Context {
    inner: Sha256,
}

impl Sha256Context for Context {
    fn new() -> Self {
        Self {
            inner: Sha256::new(),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.inner.update(bytes)
    }

    fn finalize(self) -> [u8; HASH_LEN] {
        self.inner.finalize().into()
    }
}
