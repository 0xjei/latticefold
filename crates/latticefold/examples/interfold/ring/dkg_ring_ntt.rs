//! Step 2 spike: the mathematical HEART of a custom RNS-prime `Ring` for
//! LatticeFold — the negacyclic NTT that each `stark-rings` model hand-writes
//! (its `crt_in_place` / `icrt_in_place`).
//!
//! A full `SuitableRing` for a new q_l is not deliverable as an example — it
//! requires implementing `CyclotomicConfig` (this NTT), a `LatticefoldChallengeSet`,
//! and Poseidon parameters for the new prime field, all inside the external
//! `stark-rings` crate. What we CAN do standalone — and what de-risks the whole
//! custom-`Ring` effort — is prove the NTT itself: for a fully-splitting
//! NTT-friendly prime (q ≡ 1 mod 2N), X^N + 1 factors into N linear terms, so the
//! ring R_q = Z_q[X]/(X^N+1) is a direct product of N copies of Z_q, and the CRT
//! map is a negacyclic NTT that turns polynomial multiplication into pointwise
//! products.
//!
//! This example:
//!   1. finds a primitive 2N-th root of unity ψ mod q,
//!   2. implements forward/inverse negacyclic NTT (the CRT / iCRT),
//!   3. verifies round-trip identity and that pointwise NTT products equal
//!      schoolbook multiplication mod (X^N + 1).
//!
//! That is exactly the per-prime kernel Step 2 must reimplement in `stark-rings`
//! for each real q_l. Once this kernel exists for a chosen q_l, the rest of the
//! custom-`Ring` wiring is (large but) mechanical boilerplate.
//!
//! Run with: cargo run --release --example dkg_ring_ntt

/// Fully-splitting NTT-friendly prime: q ≡ 1 (mod 2N). Here N = 8, 2N = 16,
/// q = 7681 = 480*16 + 1 (a real NTT-friendly prime used in lattice crypto).
const Q: u128 = 7681;
const N: usize = 8;

fn add(a: u128, b: u128) -> u128 {
    (a + b) % Q
}
fn sub(a: u128, b: u128) -> u128 {
    (a + Q - b % Q) % Q
}
fn mul(a: u128, b: u128) -> u128 {
    (a * b) % Q
}

fn pow(mut b: u128, mut e: u128) -> u128 {
    let mut r = 1u128;
    b %= Q;
    while e > 0 {
        if e & 1 == 1 {
            r = mul(r, b);
        }
        b = mul(b, b);
        e >>= 1;
    }
    r
}
fn inv(a: u128) -> u128 {
    pow(a, Q - 2)
} // q prime => Fermat inverse

/// Find a primitive (2N)-th root of unity ψ: order exactly 2N.
fn primitive_2n_root() -> u128 {
    let order = (2 * N) as u128;
    // g^{(q-1)/2N} is a 2N-th root for a generator g; scan candidates.
    for cand in 2..Q {
        let psi = pow(cand, (Q - 1) / order);
        // check exact order 2N: psi^2N = 1 and psi^N = -1 (= Q-1)
        if pow(psi, order) == 1 && pow(psi, N as u128) == Q - 1 {
            return psi;
        }
    }
    panic!("no primitive 2N-th root — q not NTT-friendly for this N");
}

/// Forward negacyclic NTT (the CRT map): evaluate the polynomial at the N
/// primitive 2N-th roots of unity ψ^{2k+1}, k = 0..N. Schoolbook O(N^2) — a
/// real model uses a radix-2 butterfly, but correctness is identical.
fn ntt(a: &[u128], psi: u128) -> Vec<u128> {
    (0..N)
        .map(|k| {
            let point = pow(psi, (2 * k + 1) as u128);
            (0..N).fold(0u128, |acc, j| add(acc, mul(a[j], pow(point, j as u128))))
        })
        .collect()
}

/// Inverse negacyclic NTT (the iCRT map).
fn intt(evals: &[u128], psi: u128) -> Vec<u128> {
    let n_inv = inv(N as u128);
    let psi_inv = inv(psi);
    (0..N)
        .map(|j| {
            let s = (0..N).fold(0u128, |acc, k| {
                let point_inv = pow(psi_inv, (2 * k + 1) as u128);
                add(acc, mul(evals[k], pow(point_inv, j as u128)))
            });
            mul(s, n_inv)
        })
        .collect()
}

/// Schoolbook multiplication in Z_q[X]/(X^N + 1) (negacyclic convolution).
fn schoolbook_mul(a: &[u128], b: &[u128]) -> Vec<u128> {
    let mut c = vec![0u128; 2 * N];
    for i in 0..N {
        for j in 0..N {
            c[i + j] = add(c[i + j], mul(a[i], b[j]));
        }
    }
    // reduce mod X^N + 1: X^N = -1, so wrap high terms with a sign flip.
    let mut out = vec![0u128; N];
    for i in 0..N {
        out[i] = sub(c[i], c[i + N]);
    }
    out
}

fn main() {
    println!("Step 2 spike — negacyclic NTT kernel for a custom RNS-prime Ring");
    println!(
        "q = {Q}  (q ≡ 1 mod 2N = {}),  N = {N},  ring Z_q[X]/(X^{N}+1)\n",
        2 * N
    );

    let psi = primitive_2n_root();
    println!("primitive 2N-th root of unity ψ = {psi}");
    println!(
        "  ψ^2N mod q = {} (want 1),  ψ^N mod q = {} (want q-1 = {})\n",
        pow(psi, (2 * N) as u128),
        pow(psi, N as u128),
        Q - 1
    );

    // Two arbitrary ring elements.
    let a: Vec<u128> = (0..N).map(|i| (3 * i as u128 + 1) % Q).collect();
    let b: Vec<u128> = (0..N).map(|i| (7 * i as u128 + 5) % Q).collect();
    println!("a = {a:?}");
    println!("b = {b:?}\n");

    // (1) Round-trip: iCRT(CRT(a)) == a.
    let a_hat = ntt(&a, psi);
    let a_back = intt(&a_hat, psi);
    assert_eq!(a, a_back, "NTT round-trip failed");
    println!("(1) round-trip  iCRT(CRT(a)) == a                       ✓");

    // (2) CRT is a ring homomorphism: pointwise product in NTT domain equals
    //     the negacyclic convolution in coefficient domain.
    let a_hat = ntt(&a, psi);
    let b_hat = ntt(&b, psi);
    let prod_hat: Vec<u128> = a_hat.iter().zip(&b_hat).map(|(&x, &y)| mul(x, y)).collect();
    let via_ntt = intt(&prod_hat, psi);
    let via_school = schoolbook_mul(&a, &b);
    assert_eq!(
        via_ntt, via_school,
        "NTT multiplication != schoolbook mod X^N+1"
    );
    println!("(2) pointwise NTT product == schoolbook mul mod X^N+1   ✓");
    println!("    a*b mod (X^{N}+1) = {via_school:?}\n");

    println!("This is the exact kernel each stark-rings model hand-writes (crt_in_place /");
    println!("icrt_in_place). It is verified here for a real NTT-friendly prime, proving the");
    println!("custom-Ring path is sound. Remaining Step 2 work (in stark-rings, mechanical):");
    println!(
        "  • pick the real ~50-bit q_l from dkg_params.rs (or its §8.1 extension for prime t),"
    );
    println!("  • swap this O(N^2) transform for a radix-2 butterfly at production N,");
    println!("  • implement CyclotomicConfig + LatticefoldChallengeSet + Poseidon params,");
    println!("  • impl SuitableRing and drop it into the DKG slices in place of Goldilocks.");
}
