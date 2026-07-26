//! R3 benchmark: provable share encryption under the recipient's individual
//! key, with real fhe.rs extended encryption (full `(u, e1, e2)` witness) and
//! native folding — the axis where the Noir design spent 432 C3 proofs per
//! committee round (105.64s avg each, ~45,636s tracked total at H=5/N=9).
//!
//! Each dealer's full-range share is digit-decomposed (base B, 5 limbs — the
//! same digits the R2 commitments bind); every digit is encrypted with
//! fhe.rs's `try_encrypt_extended`, proven natively per transport prime, and
//! decrypted for real; the share is recomposed and checked.
//!
//! Run with Rust 1.91.1 and the opt-in feature:
//!   cargo +1.91.1 run --release --example dkg_fhe_r3 --features fhe-bridge,parallel
//!   cargo +1.91.1 run --release --example dkg_fhe_r3 --features fhe-bridge,parallel \
//!     -- --dealers 5 --degree 8192

#[cfg(feature = "fhe-bridge")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install a large-stack rayon pool before any witness work (the fold and
    // decomposition paths overflow the default 2 MiB rayon stack at N=8192).
    latticefold::fhe_bridge::ensure_large_rayon_stack();

    use ark_ff::PrimeField;
    use cyclotomic_rings::rings::{N8192Q0RingPoly, N8192Q0Field};
    use latticefold::{
        arith::Witness,
        decomposition_parameters::DecompositionParams,
        r3_bridge::{digit_decode, digit_encode, n8192_s0, n8192_s1, R3Transport},
    };
    use rand::RngCore;
    use stark_rings::{cyclotomic_ring::CRT, PolyRing};

    let mut dealers = 5usize;
    let args: Vec<String> = std::env::args().collect();
    let mut index = 1;
    while index < args.len() {
        if args[index] == "--dealers" {
            dealers = args
                .get(index + 1)
                .ok_or("missing value for --dealers")?
                .parse()?;
            index += 2;
        } else {
            return Err(format!("unknown argument '{}'", args[index]).into());
        }
    }

    #[derive(Clone)]
    struct ShareDecomp;
    impl DecompositionParams for ShareDecomp {
        const B: u128 = 1 << 15;
        const L: usize = 5;
        const B_SMALL: usize = 2;
        const K: usize = 59;
    }

    const DEGREE: usize = 8192;
    const Q0: u64 = 0x03fffffffea00001; // threshold channel q0 (share domain)
    let digits_l = ShareDecomp::L;
    println!(
        "R3 — {dealers} dealers x {digits_l} digits x 2 transport primes, degree {DEGREE}\n\
         (reference: Noir C3 — 3.48M constraints, 10.76s isolated prove, 432 proofs/round)"
    );

    let transport = R3Transport::new(DEGREE)?;
    let [pk0_rows, pk1_rows] = transport.pk_coefficients();

    // OS CSPRNG: dealer shares are secret protocol randomness.
    let mut rng = ark_std::rand::rngs::OsRng;
    let (s0_ccs, s0_scheme) = {
        let pk0 = n8192_s0::coeffs_to_ntt(&pk0_rows[0])?;
        let pk1 = n8192_s0::coeffs_to_ntt(&pk1_rows[0])?;
        n8192_s0::r3_context(&pk0, &pk1)
    };
    let (s1_ccs, s1_scheme) = {
        let pk0 = n8192_s1::coeffs_to_ntt(&pk0_rows[1])?;
        let pk1 = n8192_s1::coeffs_to_ntt(&pk1_rows[1])?;
        n8192_s1::r3_context(&pk0, &pk1)
    };

    let start_all = std::time::Instant::now();
    let mut s0_instances = Vec::new();
    let mut s1_instances = Vec::new();
    let mut encrypt_time = std::time::Duration::ZERO;
    let mut instance_time = std::time::Duration::ZERO;

    for dealer in 0..dealers {
        // One full-range share per dealer (uniform mod the threshold q0).
        let share: Vec<u64> = (0..DEGREE).map(|_| rng.next_u64() % Q0).collect();
        let share_ntt = {
            let poly = N8192Q0RingPoly::from(
                share
                    .iter()
                    .copied()
                    .map(N8192Q0Field::from)
                    .collect::<Vec<_>>(),
            );
            CRT::elementwise_crt(vec![poly])[0]
        };
        // The digits the R2 commitment binds (balanced, signed).
        let witness = Witness::from_w_ccs::<ShareDecomp>(vec![share_ntt]);
        let digit_polys: Vec<Vec<i64>> = witness
            .f_coeff
            .iter()
            .map(|digit_poly| {
                digit_poly
                    .coeffs()
                    .iter()
                    .map(|c| {
                        let v = c.into_bigint().as_ref()[0];
                        if v > Q0 / 2 {
                            (v as i128 - Q0 as i128) as i64
                        } else {
                            v as i64
                        }
                    })
                    .collect()
            })
            .collect();

        // Transport each digit with real extended encryption + per-prime proofs.
        let mut decrypted_digits: Vec<Vec<i64>> = Vec::with_capacity(digits_l);
        for digit_poly in &digit_polys {
            let encoded: Vec<u64> = digit_poly.iter().map(|&d| digit_encode(d)).collect();
            let t0 = std::time::Instant::now();
            let (ciphertext, u, e1, e2) = transport.encrypt_digit(&encoded)?;
            encrypt_time += t0.elapsed();

            let ct0_rows = R3Transport::ciphertext_coefficients(&ciphertext, 0);
            let ct1_rows = R3Transport::ciphertext_coefficients(&ciphertext, 1);
            let u_rows = R3Transport::witness_coefficients(&u);
            let e1_rows = R3Transport::witness_coefficients(&e1);
            let e2_rows = R3Transport::witness_coefficients(&e2);

            let m_s0 = n8192_s0::signed_to_ntt(digit_poly)?;
            let m_s1 = n8192_s1::signed_to_ntt(digit_poly)?;
            let t1 = std::time::Instant::now();
            s0_instances.push(n8192_s0::r3_instance(
                &n8192_s0::coeffs_to_ntt(&ct0_rows[0])?,
                &n8192_s0::coeffs_to_ntt(&ct1_rows[0])?,
                n8192_s0::coeffs_to_ntt(&u_rows[0])?,
                n8192_s0::coeffs_to_ntt(&e1_rows[0])?,
                n8192_s0::coeffs_to_ntt(&e2_rows[0])?,
                m_s0,
                &s0_ccs,
                &s0_scheme,
            )?);
            s1_instances.push(n8192_s1::r3_instance(
                &n8192_s1::coeffs_to_ntt(&ct0_rows[1])?,
                &n8192_s1::coeffs_to_ntt(&ct1_rows[1])?,
                n8192_s1::coeffs_to_ntt(&u_rows[1])?,
                n8192_s1::coeffs_to_ntt(&e1_rows[1])?,
                n8192_s1::coeffs_to_ntt(&e2_rows[1])?,
                m_s1,
                &s1_ccs,
                &s1_scheme,
            )?);
            instance_time += t1.elapsed();

            // Real decryption of the transported digit.
            let decoded = transport.decrypt(&ciphertext)?;
            decrypted_digits.push(decoded.iter().map(|&v| digit_decode(v)).collect());
        }

        // Recompose the share from the decrypted digits and check.
        let base = ShareDecomp::B as u64;
        let mut recomposed = vec![0u64; DEGREE];
        for (limb, digits) in decrypted_digits.iter().enumerate() {
            let factor = (base as u128).pow(limb as u32) % Q0 as u128;
            for (acc, &d) in recomposed.iter_mut().zip(digits) {
                let term = if d < 0 {
                    Q0 - (((-d) as u128 * factor % Q0 as u128) as u64)
                } else {
                    (d as u128 * factor % Q0 as u128) as u64
                };
                *acc = (*acc + term) % Q0;
            }
        }
        assert_eq!(
            recomposed, share,
            "dealer {dealer}: recomposed share mismatch after R3 transport"
        );
        println!(
            "  dealer {dealer}/{dealers}: {digits_l} digits encrypted + proven + decrypted, share recomposed OK"
        );
    }

    println!(
        "\ninstance generation: {:.1}s encrypt (fhe.rs) + {:.1}s prove-build ({} instances/prime)",
        encrypt_time.as_secs_f64(),
        instance_time.as_secs_f64(),
        s0_instances.len()
    );

    // Fold per transport prime (the high-arity axis), concurrently.
    let fold_start = std::time::Instant::now();
    let (s0_result, s1_result) = std::thread::scope(|scope| {
        let h0 = std::thread::Builder::new()
            .stack_size(1 << 30)
            .spawn_scoped(scope, || {
                n8192_s0::prove_and_fold_r3(&s0_instances, &s0_ccs, &s0_scheme, 0x30)
                    .map_err(|e| e.to_string())
            })
            .expect("spawn s0 fold");
        let h1 = std::thread::Builder::new()
            .stack_size(1 << 30)
            .spawn_scoped(scope, || {
                n8192_s1::prove_and_fold_r3(&s1_instances, &s1_ccs, &s1_scheme, 0x31)
                    .map_err(|e| e.to_string())
            })
            .expect("spawn s1 fold");
        (
            h0.join().unwrap_or_else(|_| Err("s0 fold panicked".to_string())),
            h1.join().unwrap_or_else(|_| Err("s1 fold panicked".to_string())),
        )
    });
    s0_result?;
    s1_result?;
    let fold_time = fold_start.elapsed();

    let total = start_all.elapsed();
    let per_instance = total / (2 * s0_instances.len()) as u32;
    println!(
        "\n{} R3 instances ({} per prime) proven + folded in {:.1}s total ({:.1}s fold chains)",
        2 * s0_instances.len(),
        s0_instances.len(),
        total.as_secs_f64(),
        fold_time.as_secs_f64()
    );
    println!(
        "per-instance cost: {:.2}s — vs Noir C3 10.76s isolated prove (and its recursive \
         aggregation on top; here folding replaces it)",
        per_instance.as_secs_f64()
    );
    println!("R3 benchmark: validated");
    Ok(())
}

#[cfg(not(feature = "fhe-bridge"))]
fn main() {
    eprintln!("run with --features fhe-bridge");
}
