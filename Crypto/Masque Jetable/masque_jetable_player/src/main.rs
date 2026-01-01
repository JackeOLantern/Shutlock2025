#![no_std]
#![no_main]

use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

mod sys;
use sys::{getc, getrandom, write};

const FLAG: &[u8] = b"CTF/5094e1507389d939b487e6e2cccd1986/";

unsafe fn main() -> i32 {
    // Constraint on FLAG length.
    assert!(matches!(FLAG.len(), 32..40));

    while let Some(c) = getc() {
        if c == b'\n' {
            let mut rng = rng();
            let mut key = [0u8; 256];
            keygen(&mut rng, &mut key);
            // Apply encryption and format as hex
            const PACKET_LEN: usize = 48;
            let mut pkt = [0u8; 2 * PACKET_LEN + 1];
            let offset = rng.gen_range(FLAG.len()..PACKET_LEN) - FLAG.len();
            for i in 0..PACKET_LEN {
                let byte: u8 = if i < offset || i >= offset + FLAG.len() {
                    rng.gen() // random byte
                } else {
                    FLAG[i - offset]
                };
                let [b1, b2] = hex(key[byte as usize]);
                pkt[2 * i] = b1;
                pkt[2 * i + 1] = b2;
            }
            pkt[2 * PACKET_LEN] = b'\n';
            write(&pkt);
        }
    }
    0
}

const HEXDIGITS: [u8; 16] = *b"0123456789abcdef";

fn hex(c: u8) -> [u8; 2] {
    [HEXDIGITS[(c >> 4) as usize], HEXDIGITS[(c & 0xf) as usize]]
}

unsafe fn rng() -> SmallRng {
    let mut seed = [0u8; 32];
    getrandom(&mut seed);
    SmallRng::from_seed(seed)
}

fn keygen(rng: &mut SmallRng, out: &mut [u8; 256]) {
    let mut idx = [0u8; 256];
    for i in 0..256 {
        out[i] = i as u8;
        idx[i] = i as u8;
    }

    let mut idx = &mut idx[..];
    while idx.len() > 1 {
        let n = idx.len();
        let pos = rng.gen_range(0..(n - 1));
        out.swap(idx[pos] as usize, idx[n - 1] as usize);
        let fix = match n {
            2 => return,
            3 => false,
            4 => rng.gen_range(0..3) == 0,
            5 => rng.gen_range(0..11) <= 1,
            n => rng.gen_range(0..n) == 0,
        };
        if fix {
            for i in pos..(n - 2) {
                idx[i] = idx[i + 1];
            }
            idx = &mut idx[..n - 2];
        } else {
            idx = &mut idx[..n - 1];
        }
    }
}
