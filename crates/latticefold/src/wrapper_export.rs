//! Real C5-wrapper vector export: run the protocol's R1 phase with the real
//! fhe.rs-sampled committee and emit, per RNS channel, everything the
//! Schwartz–Zippel C5 wrapper consumes:
//!
//! - the aggregated R1 witness decomposition (the digit SUMS
//!   `Σ_i decompose(w_i)` the homomorphic aggregate commitment binds),
//! - the aggregate Ajtai commitment `cm_agg = Σ_i cm_i` (the free R5
//!   homomorphism check),
//! - the per-track Ajtai matrix (the `from_domain` CRS) as a generated Noir
//!   constants file,
//! - the §6.2 rank-1 outer-commitment digest of `cm_agg`, and the
//!   off-circuit Fiat–Shamir challenges (`wrapper_challenge.rs`) derived from
//!   it (commit-then-challenge, no in-circuit hashing).
//!
//! The aggregate witness digit sums are exactly what the aggregate
//! commitment binds: `sk`/`e` digits never carry (ternary/CBD sums stay
//! inside (-B/2, B/2)), and the smudging limb sums recompose to the
//! aggregated smudging noise with the looser bound `H·B/2`.

use std::error::Error;

use num_bigint::BigInt;

use crate::{
    fhe_bridge::CommitteeConfig, samples::DealerSamples, vdkg_params::VdkgParams,
};

/// One RNS channel's export for the C5 wrapper (plain data only).
#[derive(Debug, Clone)]
pub struct C5TrackExport {
    /// Channel index (0, 1, 2) and its modulus.
    pub channel: usize,
    pub modulus: u64,
    /// The track's NTT root of unity (psi) and omega = psi^2.
    pub psi: u64,
    pub omega: u64,
    /// The CRS element `a`, coefficient form.
    pub a_coeffs: Vec<u64>,
    /// The CRS element `a`, NTT form.
    pub a_ntt: Vec<u64>,
    /// Aggregated secret key `Σ sk_i`, signed coefficient form.
    pub sk_acc: Vec<i64>,
    /// Aggregated error `Σ e_i`, signed coefficient form.
    pub e_acc: Vec<i64>,
    /// Aggregated smudging limb sums per limb, signed coefficient form.
    pub esm_limbs_acc: Vec<Vec<i64>>,
    /// The committed digit sums `Σ_i decompose(w_i)[j]`, signed coefficient
    /// form (the exact vector the aggregate commitment binds).
    pub digit_sums: Vec<Vec<i64>>,
    /// The aggregate commitment `Σ_i cm_i`, kappa ring elements, NTT form.
    pub cm_acc_ntt: Vec<Vec<u64>>,
    /// The aggregate public key component `pk0_agg = Σ pk0_i`, coefficient
    /// form.
    pub pk0_agg: Vec<u64>,
    /// The §6.2 rank-1 outer-commitment digest of `cm_acc`, NTT form.
    pub digest_ntt: Vec<u64>,
    /// The Schwartz–Zippel challenge `r` (off-circuit, digest-derived).
    pub r_sz: u64,
    /// The linearization challenge point `r_lin` (off-circuit, digest-derived).
    pub r_lin: Vec<u64>,
    /// The NTT-combination challenge `rho` (off-circuit, digest-derived).
    pub rho: u64,
    /// The evaluation point `gamma` for the coefficient-domain opening check.
    pub gamma: u64,
    /// The witness digit polynomials evaluated at `gamma` (40 values).
    pub f_gamma: Vec<u64>,
    /// The Ajtai matrix evaluated at `gamma`: `A_ij(gamma)` per (row, column).
    pub a_gamma: Vec<Vec<u64>>,
    /// `Σ_j Q_ij(gamma)` per row: the quotient-polynomial evaluations of the
    /// X^N+1 reduction in the opening identity.
    pub q_sum_gamma: Vec<u64>,
    /// `cm_i(gamma)` per row: the aggregate commitment's coefficient
    /// polynomial evaluated at `gamma`.
    pub cm_gamma: Vec<u64>,
    /// The CRS element evaluated at `gamma`.
    pub a_gamma_crs: u64,
    /// `pk0_agg(gamma)` in coefficient form.
    pub pk0_gamma: u64,
    /// The R1 relation's quotient evaluation at `gamma`.
    pub q_r1_gamma: u64,
}

/// The full C5 export (one track per RNS channel).
#[derive(Debug, Clone)]
pub struct C5Export {
    pub degree: usize,
    pub plaintext_modulus: u64,
    pub committee: (usize, usize, usize),
    pub tracks: Vec<C5TrackExport>,
}

/// Run the R1 phase of the flow for the committee and export the C5 wrapper
/// vectors for all three channels. `num_ciphertexts` is the smudging z.
pub fn export_c5<P, F>(
    samples: &[DealerSamples],
    config: &CommitteeConfig,
    export_track: F,
) -> Result<C5Export, Box<dyn Error>>
where
    P: VdkgParams,
    F: Fn(&[DealerSamples], &CommitteeConfig, usize) -> Result<C5TrackExport, Box<dyn Error>>,
{
    let tracks = (0..3)
        .map(|channel| export_track(samples, config, channel))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(C5Export {
        degree: P::DEGREE,
        plaintext_modulus: P::THRESHOLD_PLAINTEXT,
        committee: (config.committee_n, config.honest_h, config.threshold_t),
        tracks,
    })
}

/// Emit the wrapper inputs: the Ajtai matrix as a Noir constants file and the
/// witness/commitment data as `Prover.toml`.
pub fn write_wrapper_files<P: VdkgParams>(
    export: &C5Export,
    ajtai: &[Vec<Vec<Vec<u64>>>], // [track][kappa][m][degree] NTT values
    out_dir: &str,
) -> Result<(), Box<dyn Error>> {
    use std::fmt::Write as _;

    std::fs::create_dir_all(format!("{out_dir}/src"))?;

    // roots.nr: moduli/roots and aggregated bound.
    let mut roots = String::from("// Auto-generated by dkg_wrapper_export - do not edit.\n");
    for track in &export.tracks {
        let t = track.channel;
        let _ = writeln!(roots, "pub global Q_{t}: u64 = {};", track.modulus);
        let _ = writeln!(roots, "pub global PSI_{t}: Field = {};", track.psi);
        let _ = writeln!(roots, "pub global OMEGA_{t}: Field = {};", track.omega);
    }
    std::fs::write(format!("{out_dir}/src/roots.nr"), roots)?;

    // ajtai_{t}.nr: the per-track Ajtai matrix as one module-level global
    // array per row (referenced directly by the circuit; no inline literals).
    for (t, matrix) in ajtai.iter().enumerate() {
        let mut src = String::from("// Auto-generated Ajtai CRS matrix (from_domain) - do not edit.\n");
        for (i, row) in matrix.iter().enumerate() {
            let entries = row
                .iter()
                .map(|poly| format!("{:?}", poly))
                .collect::<Vec<_>>()
                .join(",\n    ");
            let _ = writeln!(
                src,
                "pub global A_{t}_{i}: [[Field; {}]; {}] = [\n    {}\n];",
                matrix[0][0].len(),
                row.len(),
                entries
            );
        }
        std::fs::write(format!("{out_dir}/src/ajtai_{t}.nr"), src)?;
    }

    // Prover.toml
    let mut toml = String::new();
    let fmt_i64 = |v: &[i64], modulus: u64| {
        let mut out = String::from("[");
        for (k, x) in v.iter().enumerate() {
            if k > 0 {
                out.push_str(", ");
            }
            // Noir field inputs cannot be negative; emit canonical q + d.
            let canon = x.rem_euclid(modulus as i64);
            let _ = write!(out, "\"{canon}\"");
        }
        out.push(']');
        out
    };
    let fmt_u64 = |v: &[u64]| {
        let mut out = String::from("[");
        for (k, x) in v.iter().enumerate() {
            if k > 0 {
                out.push_str(", ");
            }
            let _ = write!(out, "\"{x}\"");
        }
        out.push(']');
        out
    };
    // The Ajtai CRS matrices live in the ajtai_{t}.nr constants files
    // (module-level global arrays), not in Prover.toml.
    for track in &export.tracks {
        let t = track.channel;
        let _ = writeln!(toml, "a_ntt_{t} = {}", fmt_u64(&track.a_ntt));
        let _ = writeln!(toml, "pk0_agg_{t} = {}", fmt_u64(&track.pk0_agg));
        let _ = writeln!(toml, "r_sz_{t} = \"{}\"", track.r_sz);
        let _ = writeln!(toml, "r_lin_{t} = {}", fmt_u64(&track.r_lin));
        let _ = writeln!(toml, "rho_{t} = \"{}\"", track.rho);
        let _ = writeln!(toml, "gamma_{t} = \"{}\"", track.gamma);
        let _ = writeln!(toml, "a_gamma_crs_{t} = \"{}\"", track.a_gamma_crs);
        let _ = writeln!(toml, "pk0_gamma_{t} = \"{}\"", track.pk0_gamma);
        let _ = writeln!(toml, "q_r1_gamma_{t} = \"{}\"", track.q_r1_gamma);
        let _ = writeln!(toml, "digest_ntt_{t} = {}", fmt_u64(&track.digest_ntt));
        let fg = track
            .f_gamma
            .iter()
            .map(|&v| format!("\"{v}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(toml, "f_gamma_{t} = [{fg}]");
        let a_gamma_flat = track
            .a_gamma
            .iter()
            .flat_map(|row| row.iter())
            .map(|&v| format!("\"{v}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(toml, "a_gamma_{t} = [{a_gamma_flat}]");
        let qsum = track
            .q_sum_gamma
            .iter()
            .map(|&v| format!("\"{v}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(toml, "q_sum_gamma_{t} = [{qsum}]");
        let cmg = track
            .cm_gamma
            .iter()
            .map(|&v| format!("\"{v}\""))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(toml, "cm_gamma_{t} = [{cmg}]");
        // Nested arrays: digit_sums (40 x degree) and cm (kappa x degree).
        let digit_rows = track
            .digit_sums
            .iter()
            .map(|row| fmt_i64(row, track.modulus))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(toml, "digit_sums_{t} = [{digit_rows}]");
        let cm_rows = track
            .cm_acc_ntt
            .iter()
            .map(|row| fmt_u64(row))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(toml, "cm_{t} = [{cm_rows}]");
    }
    // Aggregated logical witnesses (reference / cross-check).
    for track in &export.tracks {
        let t = track.channel;
        let _ = writeln!(toml, "sk_acc_{t} = {}", fmt_i64(&track.sk_acc, track.modulus));
        let _ = writeln!(toml, "e_acc_{t} = {}", fmt_i64(&track.e_acc, track.modulus));
        for (j, limb) in track.esm_limbs_acc.iter().enumerate() {
            let _ = writeln!(toml, "esm_limb_{t}_{j} = {}", fmt_i64(limb, track.modulus));
        }
    }
    std::fs::write(format!("{out_dir}/Prover.toml"), toml)?;
    Ok(())
}

/// Signed balanced representation of an i64 coefficient vector: recompose
/// helper for the export side.
pub fn recompose_signed(limbs: &[i64], base: i64) -> BigInt {
    let mut value = BigInt::from(0);
    for &digit in limbs.iter().rev() {
        value = value * base + digit;
    }
    value
}
