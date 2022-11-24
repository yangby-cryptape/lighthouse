use crate::{Sha256Context, HASH_LEN};

pub(crate) use SHA256Hash as Context;

const ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub struct SHA256Hash {
    state: [u32; 8],
    total_bits: usize,

    unprocessed: [u8; 64],
    unprocessed_len: usize,
}

impl Sha256Context for SHA256Hash {
    fn new() -> Self {
        Self::new()
    }

    fn update(&mut self, bytes: &[u8]) {
        self.update(bytes);
    }

    fn finalize(self) -> [u8; HASH_LEN] {
        self.finalize().into()
    }
}

impl SHA256Hash {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            total_bits: 0,
            unprocessed: [0; 64],
            unprocessed_len: 0,
        }
    }

    fn update_block(&mut self, block: &[u8]) {
        let mut w: [u32; 64] = [0; 64];

        {
            let mut tmp: [u8; 4] = Default::default();
            macro_rules! m1 {
                ($i:literal) => {
                    tmp.copy_from_slice(&block[$i * 4..($i + 1) * 4]);
                    w[$i] = u32::from_be_bytes(tmp);
                };
                ([ $($i:literal),+ $(,)? ]) => {
                    $( m1!($i); )+
                };
            }
            m1!([0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7]);
            m1!([0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf]);
        }

        {
            macro_rules! m2 {
                ($i:literal) => {
                    let s0 = w[$i - 15].rotate_right(7) ^ w[$i - 15].rotate_right(18) ^ (w[$i - 15] >> 3);
                    let s1 = w[$i - 2].rotate_right(17) ^ w[$i - 2].rotate_right(19) ^ (w[$i - 2] >> 10);
                    w[$i] = w[$i - 16]
                        .wrapping_add(s0)
                        .wrapping_add(w[$i - 7])
                        .wrapping_add(s1);
                };
                ([ $($i:literal),+ $(,)? ]) => {
                    $( m2!($i); )+
                };
            }
            m2!([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]);
            m2!([0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f]);
            m2!([0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27]);
            m2!([0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f]);
            m2!([0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37]);
            m2!([0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f]);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        {
            macro_rules! m3 {
                ($j:literal) => {
                    let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
                    let ch = (e & f) ^ (!e & g);
                    let temp1 = h
                        .wrapping_add(s1)
                        .wrapping_add(ch)
                        .wrapping_add(ROUND_CONSTANTS[$j])
                        .wrapping_add(w[$j]);

                    let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
                    let maj = (a & b) ^ (a & c) ^ (b & c);
                    let temp2 = s0.wrapping_add(maj);

                    h = g;
                    g = f;
                    f = e;
                    e = d.wrapping_add(temp1);
                    d = c;
                    c = b;
                    b = a;
                    a = temp1.wrapping_add(temp2);
                };
                ([ $($i:literal),+ $(,)? ]) => {
                    $( m3!($i); )+
                };
            }
            m3!([0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7]);
            m3!([0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf]);
            m3!([0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17]);
            m3!([0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f]);
            m3!([0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27]);
            m3!([0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f]);
            m3!([0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37]);
            m3!([0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f]);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    fn update(&mut self, mut input: &[u8]) {
        if input.is_empty() {
            return;
        }

        let input_len = input.len();
        self.total_bits += input_len * 8;

        let unprocessed_len = self.unprocessed_len;

        if unprocessed_len + input_len < 64 {
            self.unprocessed_len += input_len;
            (&mut self.unprocessed[unprocessed_len..self.unprocessed_len]).copy_from_slice(input);
        }

        if unprocessed_len > 0 {
            let (padding, remainder) = input.split_at(64 - unprocessed_len);
            (&mut self.unprocessed[unprocessed_len..]).copy_from_slice(padding);
            self.update_block(&self.unprocessed.clone());
            input = remainder;
            self.unprocessed_len = 0;
        }

        let mut chunks = input.chunks_exact(64);
        while let Some(block) = chunks.next() {
            self.update_block(&block)
        }
        let remainder = chunks.remainder();

        if !remainder.is_empty() {
            self.unprocessed_len = remainder.len();
            (&mut self.unprocessed[..self.unprocessed_len]).copy_from_slice(remainder);
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let padding_bits = 512 - (self.total_bits + 8 + 64) % 512;
        let padding_bytes = padding_bits / 8;

        let mut bytes = [0u8; 64];
        bytes[0] = 0x80;
        let bytes_len = 1 + padding_bytes + 8;

        let length = (self.total_bits as u64).to_be_bytes();
        (&mut bytes[bytes_len - 8..bytes_len]).copy_from_slice(&length);

        self.update(&bytes[..bytes_len]);

        macro_rules! m4 {
            ($self:ident, $buf:ident, $i:literal) => {
                $buf[($i * 4)..($i + 1) * 4].copy_from_slice(&$self.state[$i].to_be_bytes());
            };
            ($self:ident, $buf:ident, [ $($i:literal),+ $(,)? ]) => {
                $( m4!($self, $buf, $i); )+
            };
        }

        let mut buf: [u8; 32] = Default::default();
        m4!(self, buf, [0, 1, 2, 3, 4, 5, 6, 7]);
        buf
    }
}
