// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
// A no_std + alloc neural-network workload exported through a plain C ABI.
// Cargo supplies the crate graph; bpf-capsule-rt supplies panic and allocation
// integration with Capsule's load-time-sized unified heap.
#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use bpf_capsule_rt as _;

// A tiny deterministic PRNG for reproducible weights, so no data has to be
// shipped in and the native reference computes from the same seed.
struct Rng(u64);

impl Rng {
    fn next_f32(&mut self) -> f32 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        // In [-1, 1). Keeping this as a multiplication avoids pulling the
        // much larger software division routine into this example.
        (((self.0 >> 40) as u32) as f32) * (1.0 / ((1u32 << 23) as f32)) - 1.0
    }
}

struct Dense {
    rows: usize,
    cols: usize,
    w: Vec<f32>,
    b: Vec<f32>,
}

impl Dense {
    fn new(rng: &mut Rng, cols: usize, rows: usize) -> Dense {
        let mut w = vec![0f32; rows * cols];
        for value in w.iter_mut() {
            *value = rng.next_f32() * 0.5;
        }
        let mut b = vec![0f32; rows];
        for value in b.iter_mut() {
            *value = rng.next_f32() * 0.1;
        }
        Dense { rows, cols, w, b }
    }

    fn forward(&self, input: &[f32], relu: bool) -> Vec<f32> {
        let mut output = vec![0f32; self.rows];
        for row in 0..self.rows {
            let mut accumulator = self.b[row];
            let base = row * self.cols;
            for column in 0..self.cols {
                accumulator += self.w[base + column] * input[column];
            }
            output[row] = if relu && accumulator < 0.0 {
                0.0
            } else {
                accumulator
            };
        }
        output
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_run(seed: u64) -> u64 {
    let mut rng = Rng(seed | 1);

    let layer1 = Dense::new(&mut rng, 16, 32);
    let layer2 = Dense::new(&mut rng, 32, 16);
    let layer3 = Dense::new(&mut rng, 16, 8);

    let mut accumulator = 0u64;
    for iteration in 0..64u64 {
        let mut input = vec![0f32; 16];
        for (index, value) in input.iter_mut().enumerate() {
            *value = (((iteration.wrapping_mul(31).wrapping_add(index as u64)) % 17) as f32)
                * (1.0 / 17.0)
                - 0.5;
        }
        let hidden1 = layer1.forward(&input, true);
        let hidden2 = layer2.forward(&hidden1, true);
        let output = layer3.forward(&hidden2, false);
        for value in output.iter() {
            accumulator = accumulator
                .wrapping_mul(1000003)
                .wrapping_add(value.to_bits() as u64);
        }
    }
    accumulator
}

#[unsafe(no_mangle)]
pub extern "C" fn rust_force_panic() -> ! {
    panic!("bpf-capsule Rust panic regression")
}
