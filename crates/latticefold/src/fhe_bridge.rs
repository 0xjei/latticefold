//! Opt-in bridge to the pinned `fhe.rs` development branch.
//!
//! This module contains the native FHE integration path: threshold Shamir
//! sharing over the full RNS modulus Z_Q, per-channel R2 sharing proofs,
//! BFV share transport, and metadata-bound R4 commitment openings folded
//! per channel with NIFS. The sharing is done once over Z_Q and projected
//! to each RNS channel, so the per-channel shares are CRT-congruent by
//! construction.

use std::{error::Error, sync::Arc};

use ark_ff::{Field, PrimeField};
use cyclotomic_rings::rings::{
    N4096Q0ChallengeSet, N4096Q0Field, N4096Q0RingNTT, N4096Q0RingPoly, N4096Q1ChallengeSet,
    N4096Q1Field, N4096Q1RingNTT, N4096Q1RingPoly, N4096Q2ChallengeSet, N4096Q2Field,
    N4096Q2RingNTT, N4096Q2RingPoly, N8192Q0ChallengeSet, N8192Q0Field, N8192Q0RingNTT,
    N8192Q0RingPoly, N8192Q1ChallengeSet, N8192Q1Field, N8192Q1RingNTT, N8192Q1RingPoly,
    N8192Q2ChallengeSet, N8192Q2Field, N8192Q2RingNTT, N8192Q2RingPoly,
};
use fhe::bfv::{self, Encoding, Plaintext, PublicKey, SecretKey};
use fhe_rand::rng;
use fhe_traits::{FheDecoder, FheDecrypter, FheEncoder, FheEncrypter};
#[cfg(feature = "parallel")]
use rayon::prelude::*;
use stark_rings::cyclotomic_ring::CRT;
use stark_rings_linalg::SparseMatrix;

use crate::{
    arith::{r1cs::R1CS, Arith, Witness, CCCS, CCS},
    commitment::AjtaiCommitmentScheme,
    decomposition_parameters::DecompositionParams,
    nifs::{
        linearization::{
            LFLinearizationProver, LFLinearizationVerifier, LinearizationProver,
            LinearizationVerifier,
        },
        NIFSProver, NIFSVerifier,
    },
    transcript::{poseidon::PoseidonTranscript, Transcript},
    vdkg_params::{
        N4096Params, N8192Params, VdkgParams, N4096_DEGREE, N4096_THRESHOLD_MODULI,
        N4096_THRESHOLD_MODULUS_PRODUCT,
    },
};

const RECIPIENT_STRIDE: u64 = 1 << 16;
const CHANNEL_STRIDE: u64 = 1 << 32;

/// Give the global rayon pool a large worker stack: the sumcheck and folding
/// paths keep whole degree-N ring elements on the stack, and the default
/// 2 MiB rayon stack overflows nondeterministically at N = 4096 and above.
/// No-op once any global pool is installed.
#[cfg(feature = "parallel")]
pub fn ensure_large_rayon_stack() {
    let _ = rayon::ThreadPoolBuilder::new()
        .stack_size(1 << 30)
        .build_global();
}

/// No-op without the `parallel` feature.
#[cfg(not(feature = "parallel"))]
pub fn ensure_large_rayon_stack() {}

const IDX_SENDER: usize = 0;
const IDX_RECIPIENT: usize = 1;
const IDX_CHANNEL: usize = 2;
const IDX_ONE: usize = 3;
const IDX_DOMAIN: usize = 5;

/// Committee configuration for the threshold DKG demonstrations.
///
/// The three sizes are independent. `committee_n` (N) recipient points each
/// receive a share; `honest_h` (H) dealers contribute sharings that are folded
/// into the R4 accumulator; and any `threshold_t` (T) shares reconstruct the
/// secret, so the sharing polynomials have degree `T - 1`. `recipient_id`
/// selects which committee point this run transports, and `session_id`
/// domain-separates the proofs so they cannot be replayed under a different
/// committee configuration.
#[derive(Clone, Copy, Debug)]
pub struct CommitteeConfig {
    /// Total number of committee members / recipient points (N).
    pub committee_n: usize,
    /// Number of honest dealers whose sharings are folded into R4 (H).
    pub honest_h: usize,
    /// Reconstruction threshold; sharing polynomials have degree T - 1 (T).
    pub threshold_t: usize,
    /// Recipient point selected for BFV transport, in 1..=N.
    pub recipient_id: usize,
    /// Session identifier bound into every proof transcript.
    pub session_id: u64,
}

impl Default for CommitteeConfig {
    fn default() -> Self {
        // The historical H=5 / T=3 demonstration committee (N = H).
        Self {
            committee_n: 5,
            honest_h: 5,
            threshold_t: 3,
            recipient_id: 3,
            session_id: 0,
        }
    }
}

const CLI_HELP: &str = "\
DKG FHE committee demonstration

Options:
  --n <N>            committee size / recipient points (default 5)
  --h <H>            honest dealers folded into R4 (default 5)
  --t <T>            reconstruction threshold, degree T-1 (default 3)
  --recipient <ID>   recipient point in 1..=N (default 3)
  --session <ID>     session id bound into proofs (default 0)
  --help             print this help

Constraints: 0 < T <= H <= N and 1 <= recipient <= N";

impl CommitteeConfig {
    /// Check the `0 < T <= H <= N` and `1 <= recipient <= N` invariants.
    pub fn validate(&self) -> Result<(), Box<dyn Error>> {
        if !(0 < self.threshold_t
            && self.threshold_t <= self.honest_h
            && self.honest_h <= self.committee_n)
        {
            return Err(format!(
                "committee configuration must satisfy 0 < T <= H <= N \
                 (got N={}, H={}, T={})",
                self.committee_n, self.honest_h, self.threshold_t
            )
            .into());
        }
        if !(1 <= self.recipient_id && self.recipient_id <= self.committee_n) {
            return Err(format!(
                "recipient_id must be in 1..=N (got recipient={}, N={})",
                self.recipient_id, self.committee_n
            )
            .into());
        }
        Ok(())
    }

    /// Parse `--n --h --t --recipient --session` from the process arguments,
    /// falling back to the demonstration defaults, then validate the result.
    ///
    /// `--help` prints usage and exits the process.
    pub fn from_env_args() -> Result<Self, Box<dyn Error>> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        let mut config = Self::default();
        let mut index = 0;
        while index < args.len() {
            let flag = args[index].as_str();
            if flag == "--help" {
                println!("{CLI_HELP}");
                std::process::exit(0);
            }
            let value = args
                .get(index + 1)
                .ok_or_else(|| format!("missing value for {flag}"))?;
            match flag {
                "--n" => config.committee_n = value.parse()?,
                "--h" => config.honest_h = value.parse()?,
                "--t" => config.threshold_t = value.parse()?,
                "--recipient" => config.recipient_id = value.parse()?,
                "--session" => config.session_id = value.parse()?,
                other => {
                    return Err(format!("unknown argument '{other}'\n\n{CLI_HELP}").into())
                }
            }
            index += 2;
        }
        config.validate()?;
        Ok(config)
    }

    /// R2 witness layout is `[secret, Y_1, ..., Y_N]`, length `1 + N`.
    fn r2_witness_len(&self) -> usize {
        1 + self.committee_n
    }

    /// Number of live R2 constraint rows: `(N - T)` GRS parity rows plus one
    /// Lagrange-at-zero consistency row.
    fn r2_constraint_rows(&self) -> usize {
        (self.committee_n - self.threshold_t) + 1
    }

    /// Padded R2 matrix row count. Driven by the committed witness width
    /// `(1 + N) * L`, but never smaller than the live constraint count.
    fn r2_ccs_rows(&self) -> usize {
        usize::max(
            self.r2_witness_len() * NativeR4Params::L,
            self.r2_constraint_rows(),
        )
        .next_power_of_two()
    }
}

#[derive(Clone)]
struct NativeR4Params;

impl DecompositionParams for NativeR4Params {
    const B: u128 = 1 << 15;
    const L: usize = 5;
    const B_SMALL: usize = 2;
    // The q channels are 34-bit fields; retain enough binary limbs for signed
    // field representatives and the public-input decomposition used by NIFS.
    const K: usize = 35;
}

#[derive(Clone)]
struct Native8192R4Params;

impl DecompositionParams for Native8192R4Params {
    const B: u128 = 1 << 15;
    const L: usize = 5;
    const B_SMALL: usize = 2;
    // The q channels are 58-bit fields; retain enough binary limbs for signed
    // field representatives and the public-input decomposition used by NIFS.
    const K: usize = 59;
}

/// Encrypt and decrypt one polynomial share using the individual BFV
/// transport instance (N=4096 parameter set).
pub fn round_trip_share(share: u64) -> Result<Vec<u64>, Box<dyn Error>> {
    let mut message = vec![0u64; N4096_DEGREE];
    message[0] = share;
    round_trip_poly_share(&message)
}

/// Encrypt and decrypt a complete degree-N polynomial share (N=4096 set).
pub fn round_trip_poly_share(message: &[u64]) -> Result<Vec<u64>, Box<dyn Error>> {
    ShareTransport::<N4096Params>::new()?.round_trip(message)
}

/// One recipient BFV transport instance shared across channels and dealers.
pub struct ShareTransport<P: VdkgParams = N4096Params> {
    params: Arc<bfv::BfvParameters>,
    secret_key: SecretKey,
    public_key: PublicKey,
    _marker: std::marker::PhantomData<P>,
}

impl<P: VdkgParams> ShareTransport<P> {
    /// Build the individual BFV transport parameters and key pair.
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let params: Arc<bfv::BfvParameters> = bfv::BfvParametersBuilder::new()
            .set_degree(P::DEGREE)
            .set_plaintext_modulus(P::SHARE_PLAINTEXT)
            .set_moduli(&P::SHARE_MODULI)
            .set_variance(10)
            .build_arc()?;

        let mut key_rng = rng();
        let secret_key = SecretKey::random(&params, &mut key_rng);
        let public_key = PublicKey::new(&secret_key, &mut key_rng);
        Ok(Self {
            params,
            secret_key,
            public_key,
            _marker: std::marker::PhantomData,
        })
    }

    fn round_trip(&self, message: &[u64]) -> Result<Vec<u64>, Box<dyn Error>> {
        if message.len() != P::DEGREE {
            return Err(format!(
                "share has {} coefficients, expected {}",
                message.len(),
                P::DEGREE
            )
            .into());
        }
        if message
            .iter()
            .any(|&coefficient| coefficient >= P::SHARE_PLAINTEXT)
        {
            return Err("share does not fit the transport plaintext modulus".into());
        }

        let plaintext = Plaintext::try_encode(message, Encoding::poly(), &self.params)?;

        let mut encryption_rng = rng();
        let ciphertext = self
            .public_key
            .try_encrypt(&plaintext, &mut encryption_rng)?;
        let decrypted = self.secret_key.try_decrypt(&ciphertext)?;
        Ok(Vec::<u64>::try_decode(&decrypted, Encoding::poly())?)
    }
}

fn metadata_domain(
    sender_id: u64,
    recipient_id: u64,
    channel_id: u64,
    field_modulus: u64,
) -> Result<u64, Box<dyn Error>> {
    let recipient_component = RECIPIENT_STRIDE
        .checked_mul(recipient_id)
        .ok_or("recipient metadata component overflow")?;
    let channel_component = CHANNEL_STRIDE
        .checked_mul(channel_id)
        .ok_or("channel metadata component overflow")?;
    let domain = sender_id
        .checked_add(recipient_component)
        .and_then(|value| value.checked_add(channel_component))
        .ok_or("metadata domain overflow")?;
    if domain >= field_modulus {
        return Err("metadata domain does not fit the channel public-input field".into());
    }
    Ok(domain)
}

/// Threshold Shamir sharing over the full RNS modulus Z_Q.
///
/// Each coefficient of the secret polynomial is shared with an independent
/// degree T-1 polynomial over Z_Q. Projecting the shares mod each q channel
/// yields per-channel sharings that agree with the Z_Q sharing under CRT.
pub struct ZqSharing {
    /// Secret polynomial coefficients, reduced mod Q.
    pub secret: Vec<u128>,
    /// One share polynomial per committee member, evaluated at x = 1..=H.
    pub shares: Vec<Vec<u128>>,
}

fn mul_mod_q(a: u128, b: u128) -> u128 {
    // Q < 2^100, so a plain `a * b` would overflow u128 (2^200) whenever both
    // operands are near Q — which happens in the degree-(T-1) Horner evaluation
    // once a power x^k mod Q grows to full size. Reduce with a division-free
    // double-and-add instead: every intermediate stays below 2^101 < 2^128.
    const Q: u128 = N4096_THRESHOLD_MODULUS_PRODUCT;
    let mut a = a % Q;
    let mut b = b % Q;
    let mut result = 0u128;
    while b != 0 {
        if b & 1 == 1 {
            result += a;
            if result >= Q {
                result -= Q;
            }
        }
        a <<= 1;
        if a >= Q {
            a -= Q;
        }
        b >>= 1;
    }
    result
}

/// Generate a degree `T - 1` sharing of a secret polynomial over Z_Q, with one
/// share per committee point `x = 1..=N`.
pub fn generate_zq_sharing(
    secret: &[u64],
    config: &CommitteeConfig,
    rng: &mut impl rand::Rng,
) -> ZqSharing {
    let q = N4096_THRESHOLD_MODULUS_PRODUCT;
    let secret_mod_q = secret
        .iter()
        .map(|&coefficient| coefficient as u128 % q)
        .collect::<Vec<_>>();

    // Independent random coefficients a_1..a_{T-1} per secret coefficient.
    let randomness: Vec<Vec<u128>> = (0..secret.len())
        .map(|_| {
            (1..config.threshold_t)
                .map(|_| {
                    let raw = ((rng.next_u64() as u128) << 64) | rng.next_u64() as u128;
                    raw % q
                })
                .collect()
        })
        .collect();

    let shares = (1..=config.committee_n as u128)
        .map(|x| {
            // x^1..x^{T-1} mod Q depend only on the evaluation point, so hoist
            // them out of the per-coefficient loop over the 4096 coefficients.
            let mut powers = Vec::with_capacity(config.threshold_t.saturating_sub(1));
            let mut power = 1u128;
            for _ in 1..config.threshold_t {
                power = mul_mod_q(power, x);
                powers.push(power);
            }
            secret_mod_q
                .iter()
                .zip(&randomness)
                .map(|(&constant, coefficients)| {
                    let mut value = constant;
                    for (&coefficient, &power) in coefficients.iter().zip(&powers) {
                        value = (value + mul_mod_q(coefficient, power)) % q;
                    }
                    value
                })
                .collect::<Vec<_>>()
        })
        .collect();

    ZqSharing {
        secret: secret_mod_q,
        shares,
    }
}

/// Project a Z_Q polynomial to one RNS channel.
pub fn project_channel(values: &[u128], channel: usize) -> Vec<u64> {
    let modulus = N4096_THRESHOLD_MODULI[channel] as u128;
    values
        .iter()
        .map(|&value| (value % modulus) as u64)
        .collect()
}

/// The whole committee's sharing material on a single RNS channel: per-dealer
/// secrets and per-dealer, per-recipient shares, all reduced mod q_l.
///
/// This is the canonical input of the per-channel R2/R4 machinery. It can be
/// produced either by projecting Z_Q sharings (the N=4096 path) or by
/// sampling the sharing polynomials directly on the channel
/// ([`generate_channel_sharing`], used when Q does not fit `u128`).
pub struct ChannelSharings {
    /// Per-dealer secret polynomials on this channel.
    pub secrets: Vec<Vec<u64>>,
    /// Per-dealer, per-recipient share polynomials on this channel.
    pub shares: Vec<Vec<Vec<u64>>>,
}

/// Project a committee's Z_Q sharings to one RNS channel.
pub fn project_sharings(sharings: &[ZqSharing], channel: usize) -> ChannelSharings {
    ChannelSharings {
        secrets: sharings
            .iter()
            .map(|sharing| project_channel(&sharing.secret, channel))
            .collect(),
        shares: sharings
            .iter()
            .map(|sharing| {
                sharing
                    .shares
                    .iter()
                    .map(|share| project_channel(share, channel))
                    .collect()
            })
            .collect(),
    }
}

/// Generate the committee's sharings directly on one RNS channel: every
/// dealer's secret polynomial (short, so identical across channels) is shared
/// with an independent random degree `T - 1` polynomial over Z_{q_l}.
///
/// Per plan.md R2, the sharing relation is defined per channel
/// (`Y_l[k] in R_{q_l}`), so sampling the sharing on the channel is the native
/// formulation; the channel sharings of one short secret are consistent with a
/// single Z_Q sharing under CRT.
pub fn generate_channel_sharing<P: VdkgParams>(
    secrets: &[Vec<u64>],
    config: &CommitteeConfig,
    channel: usize,
    rng: &mut impl rand::Rng,
) -> ChannelSharings {
    let modulus = P::THRESHOLD_MODULI[channel];
    let shares = secrets
        .iter()
        .map(|secret| {
            let randomness = (0..secret.len())
                .map(|_| {
                    (1..config.threshold_t)
                        .map(|_| rng.next_u64() % modulus)
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            (1..=config.committee_n as u64)
                .map(|x| {
                    secret
                        .iter()
                        .zip(&randomness)
                        .map(|(&constant, coefficients)| {
                            let mut value = constant as u128;
                            let mut power = 1u128;
                            for &coefficient in coefficients {
                                power = power * x as u128 % modulus as u128;
                                value = (value + coefficient as u128 * power) % modulus as u128;
                            }
                            value as u64
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        })
        .collect();
    ChannelSharings {
        secrets: secrets.to_vec(),
        shares,
    }
}

/// Garner CRT reconstruction of the three channel residues into Z_Q.
pub fn crt_combine(residues: [u64; 3]) -> u128 {
    let [q0, q1, q2] = N4096_THRESHOLD_MODULI;
    let inv = |a: u128, modulus: u128| {
        // Fermat inversion; the channel moduli are prime.
        let mut result = 1u128;
        let mut base = a % modulus;
        let mut exponent = modulus - 2;
        while exponent != 0 {
            if exponent & 1 == 1 {
                result = result * base % modulus;
            }
            base = base * base % modulus;
            exponent >>= 1;
        }
        result
    };

    let r0 = residues[0] as u128;
    let t1 = (residues[1] as u128 + q1 as u128 - r0 % q1 as u128) * inv(q0 as u128, q1 as u128)
        % q1 as u128;
    let x01 = r0 + q0 as u128 * t1;
    let t2 = (residues[2] as u128 + q2 as u128 - x01 % q2 as u128)
        * inv(q0 as u128 * q1 as u128 % q2 as u128, q2 as u128)
        % q2 as u128;
    x01 + q0 as u128 * q1 as u128 * t2
}

macro_rules! define_channel_bridge {
    ($module:ident, $params:ty, $decomp:ty, $ring:ty, $poly:ty, $field:ty, $challenge_set:ty, $channel:expr) => {
        pub mod $module {
            use super::*;

            type ChannelTranscript = PoseidonTranscript<$ring, $challenge_set>;

            pub const CHANNEL: usize = $channel;

            pub fn modulus() -> u64 {
                <$params as VdkgParams>::THRESHOLD_MODULI[CHANNEL]
            }

            fn degree() -> usize {
                <$params as VdkgParams>::DEGREE
            }

            fn scalar_ring(value: $field) -> $ring {
                <$ring>::from(value.into_bigint().as_ref()[0] as u128)
            }

            /// Domain-separate a transcript by the committee configuration and
            /// channel so a proof cannot be replayed under a different N/H/T,
            /// session, or RNS channel. Prover and verifier absorb the same
            /// values, so honest runs are unaffected.
            fn absorb_config(transcript: &mut ChannelTranscript, config: &CommitteeConfig) {
                for value in [
                    config.session_id,
                    config.committee_n as u64,
                    config.honest_h as u64,
                    config.threshold_t as u64,
                    CHANNEL as u64,
                ] {
                    transcript.absorb(&<$ring>::from(value as u128));
                }
            }

            fn share_points(n: usize) -> Vec<$field> {
                (1..=n as u64).map(<$field>::from).collect()
            }

            fn dual_multipliers(points: &[$field]) -> Vec<$field> {
                points
                    .iter()
                    .enumerate()
                    .map(|(index, &point)| {
                        points
                            .iter()
                            .enumerate()
                            .filter(|(other, _)| *other != index)
                            .fold(<$field>::ONE, |acc, (_, &other)| acc * (point - other))
                            .inverse()
                            .unwrap()
                    })
                    .collect()
            }

            fn lagrange_at_zero(points: &[$field]) -> Vec<$field> {
                points
                    .iter()
                    .enumerate()
                    .map(|(index, &point)| {
                        points
                            .iter()
                            .enumerate()
                            .filter(|(other, _)| *other != index)
                            .fold(<$field>::ONE, |acc, (_, &other)| {
                                acc * other * (other - point).inverse().unwrap()
                            })
                    })
                    .collect()
            }

            fn share_to_ntt(share: &[u64]) -> Result<$ring, Box<dyn Error>> {
                if share.len() != degree() {
                    return Err(format!(
                        "share has {} coefficients, expected {}",
                        share.len(),
                        degree()
                    )
                    .into());
                }
                if share.iter().any(|&coefficient| coefficient >= modulus()) {
                    return Err("share is not in the channel threshold domain".into());
                }
                let coefficients = share
                    .iter()
                    .copied()
                    .map(<$field>::from)
                    .collect::<Vec<_>>();
                let polynomial = <$poly>::from(coefficients);
                Ok(CRT::elementwise_crt(vec![polynomial])[0])
            }

            /// Recover the constant term of the shared secret from any T
            /// shares by Lagrange interpolation at zero.
            pub fn reconstruct_constant(
                shares: &[(u64, u64)], // (evaluation point, share constant term)
            ) -> Result<u64, Box<dyn Error>> {
                if shares.is_empty() {
                    return Err("reconstruction requires at least one share".into());
                }
                let points = shares
                    .iter()
                    .map(|&(x, _)| <$field>::from(x))
                    .collect::<Vec<_>>();
                let multipliers = lagrange_at_zero(&points);
                let secret = shares
                    .iter()
                    .zip(&multipliers)
                    .fold(<$field>::ZERO, |acc, (&(_, y), &multiplier)| {
                        acc + <$field>::from(y) * multiplier
                    });
                Ok(secret.into_bigint().as_ref()[0])
            }

            fn r2_r1cs(config: &CommitteeConfig) -> R1CS<$ring> {
                let one = <$ring>::from(1u128);
                let rows = config.r2_ccs_rows();
                let ncols = config.r2_witness_len() + 1;
                let points = share_points(config.committee_n);
                let dual = dual_multipliers(&points);
                let zero_multipliers = lagrange_at_zero(&points[..config.threshold_t]);

                let mut a_rows = vec![vec![]; rows];
                let mut b_rows = vec![vec![]; rows];
                let c_rows = vec![vec![]; rows];

                // The witness layout is [one, s0, Y_1, ..., Y_N].
                //
                // Generalized Reed-Solomon syndrome rows: for j < N - T,
                // sum_i d_i x_i^j Y_i = 0 exactly when the codeword has
                // degree at most T - 1.
                for syndrome in 0..config.committee_n - config.threshold_t {
                    a_rows[syndrome] = dual
                        .iter()
                        .zip(&points)
                        .enumerate()
                        .map(|(index, (&multiplier, &point))| {
                            let weight = multiplier * point.pow([syndrome as u64]);
                            (scalar_ring(weight), 2 + index)
                        })
                        .collect();
                    b_rows[syndrome] = vec![(one, 0)];
                }

                // Lagrange-at-zero consistency over the first T shares:
                // sum_i lambda_i Y_i - s0 = 0.
                let consistency = config.committee_n - config.threshold_t;
                a_rows[consistency] = std::iter::once((-one, 1))
                    .chain(
                        zero_multipliers
                            .iter()
                            .enumerate()
                            .map(|(index, &multiplier)| (scalar_ring(multiplier), 2 + index)),
                    )
                    .collect();
                b_rows[consistency] = vec![(one, 0)];

                R1CS::<$ring> {
                    l: 0,
                    A: SparseMatrix {
                        nrows: rows,
                        ncols,
                        coeffs: a_rows,
                    },
                    B: SparseMatrix {
                        nrows: rows,
                        ncols,
                        coeffs: b_rows,
                    },
                    C: SparseMatrix {
                        nrows: rows,
                        ncols,
                        coeffs: c_rows,
                    },
                }
            }

            /// Prove that the N channel shares form a degree T-1 sharing of
            /// the secret via one linearized R2 relation.
            pub fn prove_r2_sharing(
                secret: &[u64],
                shares: &[Vec<u64>],
                config: &CommitteeConfig,
            ) -> Result<(), Box<dyn Error>> {
                if shares.len() != config.committee_n {
                    return Err("R2 relation requires exactly N shares".into());
                }
                let secret_ntt = share_to_ntt(secret)?;
                let share_ntts = shares
                    .iter()
                    .map(|share| share_to_ntt(share))
                    .collect::<Result<Vec<_>, _>>()?;
                let ccs = CCS::from_r1cs(r2_r1cs(config), config.r2_ccs_rows());

                let mut z = vec![<$ring>::from(1u128), secret_ntt];
                z.extend(share_ntts.iter().copied());
                ccs.check_relation(&z)?;

                let scheme = AjtaiCommitmentScheme::from_domain::<ChannelTranscript>(
                    &format!("vdkg/r2/q{}/N{}", CHANNEL, degree()),
                    4,
                    config.r2_witness_len() * <$decomp>::L,
                    degree(),
                );
                let witness = Witness::from_w_ccs::<$decomp>(
                    std::iter::once(secret_ntt)
                        .chain(share_ntts.iter().copied())
                        .collect(),
                );
                let cm = CCCS {
                    cm: witness.commit::<$decomp>(&scheme)?,
                    x_ccs: vec![],
                };

                let mut prover_transcript = ChannelTranscript::default();
                absorb_config(&mut prover_transcript, config);
                let (prover_lcccs, proof) =
                    LFLinearizationProver::<$ring, ChannelTranscript>::prove(
                        &cm,
                        &witness,
                        &mut prover_transcript,
                        &ccs,
                    )?;
                let mut verifier_transcript = ChannelTranscript::default();
                absorb_config(&mut verifier_transcript, config);
                let verifier_lcccs = LFLinearizationVerifier::<$ring, ChannelTranscript>::verify(
                    &cm,
                    &proof,
                    &mut verifier_transcript,
                    &ccs,
                )?;
                assert_eq!(prover_lcccs, verifier_lcccs, "R2 linearization mismatch");
                Ok(())
            }

            fn opening_r1cs() -> R1CS<$ring> {
                let one = <$ring>::from(1u128);
                let sender = <$ring>::from(1u128);
                let recipient = <$ring>::from(RECIPIENT_STRIDE as u128);
                let channel = <$ring>::from(CHANNEL_STRIDE as u128);
                let mut a_rows = vec![vec![]; 16];
                a_rows[0] = vec![
                    (one, IDX_DOMAIN),
                    (-sender, IDX_SENDER),
                    (-recipient, IDX_RECIPIENT),
                    (-channel, IDX_CHANNEL),
                ];
                let mut b_rows = vec![vec![]; 16];
                b_rows[0] = vec![(one, IDX_ONE)];
                R1CS::<$ring> {
                    l: 3,
                    A: SparseMatrix {
                        nrows: 16,
                        ncols: 6,
                        coeffs: a_rows,
                    },
                    B: SparseMatrix {
                        nrows: 16,
                        ncols: 6,
                        coeffs: b_rows,
                    },
                    C: SparseMatrix {
                        nrows: 16,
                        ncols: 6,
                        coeffs: vec![vec![]; 16],
                    },
                }
            }

            fn public_metadata(sender_id: u64, recipient_id: u64) -> Vec<$ring> {
                vec![
                    <$ring>::from(sender_id as u128),
                    <$ring>::from(recipient_id as u128),
                    <$ring>::from(CHANNEL as u128),
                ]
            }

            pub fn r4_context() -> (CCS<$ring>, AjtaiCommitmentScheme<$ring>) {
                (
                    CCS::from_r1cs(opening_r1cs(), 16),
                    AjtaiCommitmentScheme::from_domain::<ChannelTranscript>(
                        &format!("vdkg/r4/q{}/N{}", CHANNEL, degree()),
                        4,
                        2 * <$decomp>::L,
                        degree(),
                    ),
                )
            }

            pub fn r4_instance(
                decoded: &[u64],
                sender_id: u64,
                recipient_id: u64,
                ccs: &CCS<$ring>,
                scheme: &AjtaiCommitmentScheme<$ring>,
            ) -> Result<(CCCS<$ring>, Witness<$ring>, $ring), Box<dyn Error>> {
                let share_ntt = share_to_ntt(decoded)?;
                let domain_tag = <$ring>::from(metadata_domain(
                    sender_id,
                    recipient_id,
                    CHANNEL as u64,
                    modulus(),
                )? as u128);
                let metadata = public_metadata(sender_id, recipient_id);
                let z = vec![
                    metadata[IDX_SENDER],
                    metadata[IDX_RECIPIENT],
                    metadata[IDX_CHANNEL],
                    <$ring>::from(1u128),
                    share_ntt,
                    domain_tag,
                ];
                ccs.check_relation(&z)?;

                let witness = Witness::from_w_ccs::<$decomp>(vec![share_ntt, domain_tag]);
                let cm = CCCS {
                    cm: witness.commit::<$decomp>(scheme)?,
                    x_ccs: metadata,
                };
                Ok((cm, witness, domain_tag))
            }

            /// Prove one metadata-bound R4 opening, then re-open and tamper
            /// with the commitment as sanity checks.
            pub fn prove_r4_opening(
                decoded: &[u64],
                sender_id: u64,
                recipient_id: u64,
                config: &CommitteeConfig,
            ) -> Result<(), Box<dyn Error>> {
                let (ccs, scheme) = r4_context();
                let (cm, witness, domain_tag) =
                    r4_instance(decoded, sender_id, recipient_id, &ccs, &scheme)?;

                let mut prover_transcript = ChannelTranscript::default();
                absorb_config(&mut prover_transcript, config);
                let (prover_lcccs, proof) =
                    LFLinearizationProver::<$ring, ChannelTranscript>::prove(
                        &cm,
                        &witness,
                        &mut prover_transcript,
                        &ccs,
                    )?;

                let mut verifier_transcript = ChannelTranscript::default();
                absorb_config(&mut verifier_transcript, config);
                let verifier_lcccs = LFLinearizationVerifier::<$ring, ChannelTranscript>::verify(
                    &cm,
                    &proof,
                    &mut verifier_transcript,
                    &ccs,
                )?;
                assert_eq!(prover_lcccs, verifier_lcccs, "R4 linearization mismatch");

                let metadata = public_metadata(sender_id, recipient_id);
                assert_eq!(
                    verifier_lcccs.x_w, metadata,
                    "R4 verifier output was not bound to sender/recipient metadata"
                );

                let reopened =
                    Witness::from_w_ccs::<$decomp>(vec![witness.w_ccs[0], domain_tag]);
                assert_eq!(
                    cm.cm,
                    reopened.commit::<$decomp>(&scheme)?,
                    "R4 commitment did not reopen to the transported share"
                );

                let mut tampered = decoded.to_vec();
                tampered[0] = (tampered[0] + 1) % modulus();
                let tampered_witness = Witness::from_w_ccs::<$decomp>(vec![
                    share_to_ntt(&tampered)?,
                    domain_tag,
                ]);
                assert_ne!(
                    cm.cm,
                    tampered_witness.commit::<$decomp>(&scheme)?,
                    "R4 commitment accepted a tampered transported share"
                );

                let changed_metadata = public_metadata(sender_id + 1, recipient_id);
                assert_ne!(
                    verifier_lcccs.x_w, changed_metadata,
                    "R4 metadata binding accepted a different sender"
                );

                Ok(())
            }

            /// Fold a batch of metadata-bound R4 instances into one accumulator.
            ///
            /// Each fold runs the NIFS prover; the matching NIFS verifier is a
            /// self-check that costs about as much as the prover, so it roughly
            /// doubles the (sequential) fold-chain time. Folding is the prover's
            /// job — verification is the verifier's — so the per-fold verify is
            /// deferred by default and re-enabled with `DKG_VERIFY_FOLDS=1`,
            /// which replays the whole chain through the verifier and asserts
            /// every folded accumulator matches.
            pub fn fold_r4_instances(
                instances: &[(CCCS<$ring>, Witness<$ring>)],
                ccs: &CCS<$ring>,
                scheme: &AjtaiCommitmentScheme<$ring>,
                config: &CommitteeConfig,
            ) -> Result<(), Box<dyn Error>> {
                let verify_folds = std::env::var_os("DKG_VERIFY_FOLDS").is_some();

                let (cm0, witness0) = &instances[0];
                let mut bootstrap_prover = ChannelTranscript::default();
                absorb_config(&mut bootstrap_prover, config);
                let (mut accumulator, _) =
                    LFLinearizationProver::<$ring, ChannelTranscript>::prove(
                        cm0,
                        witness0,
                        &mut bootstrap_prover,
                        ccs,
                    )?;
                let mut accumulator_witness = witness0.clone();

                let mut fold_prover = ChannelTranscript::default();
                let mut fold_verifier = ChannelTranscript::default();
                absorb_config(&mut fold_prover, config);
                absorb_config(&mut fold_verifier, config);
                for (index, (cm_i, witness_i)) in instances.iter().enumerate().skip(1) {
                    let (new_accumulator, new_witness, proof) =
                        NIFSProver::<$ring, $decomp, ChannelTranscript>::prove(
                            &accumulator,
                            &accumulator_witness,
                            cm_i,
                            witness_i,
                            &mut fold_prover,
                            ccs,
                            scheme,
                        )?;
                    if verify_folds {
                        let verified_accumulator =
                            NIFSVerifier::<$ring, $decomp, ChannelTranscript>::verify(
                                &accumulator,
                                cm_i,
                                &proof,
                                &mut fold_verifier,
                                ccs,
                            )?;
                        assert_eq!(
                            new_accumulator, verified_accumulator,
                            "R4 fold mismatch at {index}"
                        );
                    }
                    accumulator = new_accumulator;
                    accumulator_witness = new_witness;
                }
                Ok(())
            }

            /// Run the H-dealer committee on this channel: N-share R2 sharing
            /// proofs, BFV transport of the recipient's share, and one folded
            /// R4 accumulator over all received openings. The `sharings`
            /// struct holds the H honest dealer sharings folded into R4,
            /// already reduced to this channel.
            pub fn fold_committee_r4(
                transport: &ShareTransport<$params>,
                sharings: &ChannelSharings,
                config: &CommitteeConfig,
            ) -> Result<Vec<Vec<u64>>, Box<dyn Error>> {
                ensure_large_rayon_stack();
                let recipient_id = config.recipient_id as u64;
                let (ccs, scheme) = r4_context();

                // Each dealer's R2 sharing proof, BFV transport, and R4 instance
                // construction are independent, so they run in parallel across
                // the committee. Errors are stringified to keep the closure's
                // return type `Send`; only the final NIFS fold chain below is
                // inherently sequential. Results collect in dealer order.
                let process = |dealer_index: usize|
                    -> Result<(Vec<u64>, (CCCS<$ring>, Witness<$ring>)), String> {
                    let sender_id = dealer_index as u64 + 1;
                    let secret = &sharings.secrets[dealer_index];
                    let shares = &sharings.shares[dealer_index];
                    prove_r2_sharing(secret, shares, config).map_err(|e| e.to_string())?;

                    let decoded = transport
                        .round_trip(&shares[(recipient_id - 1) as usize])
                        .map_err(|e| e.to_string())?;
                    let (cm, witness, _) =
                        r4_instance(&decoded, sender_id, recipient_id, &ccs, &scheme)
                            .map_err(|e| e.to_string())?;
                    Ok((decoded, (cm, witness)))
                };

                let dealer_start = std::time::Instant::now();
                #[cfg(feature = "parallel")]
                let processed = (0..sharings.secrets.len())
                    .into_par_iter()
                    .map(process)
                    .collect::<Result<Vec<_>, String>>()?;
                #[cfg(not(feature = "parallel"))]
                let processed = (0..sharings.secrets.len())
                    .map(process)
                    .collect::<Result<Vec<_>, String>>()?;
                if std::env::var_os("DKG_PHASE_TIMING").is_some() {
                    eprintln!(
                        "[q{CHANNEL}] dealer phase ({} dealers R2+BFV+R4): {:.1}s",
                        sharings.secrets.len(),
                        dealer_start.elapsed().as_secs_f64()
                    );
                }

                let mut decoded_shares = Vec::with_capacity(processed.len());
                let mut instances = Vec::with_capacity(processed.len());
                for (decoded, instance) in processed {
                    decoded_shares.push(decoded);
                    instances.push(instance);
                }

                let fold_start = std::time::Instant::now();
                fold_r4_instances(&instances, &ccs, &scheme, config)?;
                if std::env::var_os("DKG_PHASE_TIMING").is_some() {
                    eprintln!(
                        "[q{CHANNEL}] fold chain ({} folds): {:.1}s",
                        instances.len().saturating_sub(1),
                        fold_start.elapsed().as_secs_f64()
                    );
                }
                Ok(decoded_shares)
            }
        }
    };
}

define_channel_bridge!(
    q0,
    N4096Params,
    NativeR4Params,
    N4096Q0RingNTT,
    N4096Q0RingPoly,
    N4096Q0Field,
    N4096Q0ChallengeSet,
    0
);
define_channel_bridge!(
    q1,
    N4096Params,
    NativeR4Params,
    N4096Q1RingNTT,
    N4096Q1RingPoly,
    N4096Q1Field,
    N4096Q1ChallengeSet,
    1
);
define_channel_bridge!(
    q2,
    N4096Params,
    NativeR4Params,
    N4096Q2RingNTT,
    N4096Q2RingPoly,
    N4096Q2Field,
    N4096Q2ChallengeSet,
    2
);
define_channel_bridge!(
    n8192_q0,
    N8192Params,
    Native8192R4Params,
    N8192Q0RingNTT,
    N8192Q0RingPoly,
    N8192Q0Field,
    N8192Q0ChallengeSet,
    0
);
define_channel_bridge!(
    n8192_q1,
    N8192Params,
    Native8192R4Params,
    N8192Q1RingNTT,
    N8192Q1RingPoly,
    N8192Q1Field,
    N8192Q1ChallengeSet,
    1
);
define_channel_bridge!(
    n8192_q2,
    N8192Params,
    Native8192R4Params,
    N8192Q2RingNTT,
    N8192Q2RingPoly,
    N8192Q2Field,
    N8192Q2ChallengeSet,
    2
);

/// Run the real BFV transport and prove one native q0 R4 commitment opening.
pub fn round_trip_share_and_prove_r4(share: u64) -> Result<(), Box<dyn Error>> {
    let decoded = round_trip_share(share)?;
    q0::prove_r4_opening(&decoded, 1, 2, &CommitteeConfig::default())
}

/// Generate a threshold Shamir share over Z_Q, transport the recipient's q0
/// projection with BFV, and bind its R4 opening to the sender, recipient, and
/// channel metadata.
pub fn round_trip_shamir_share_and_prove_r4(
    secret: u64,
    sender_id: u64,
    recipient_id: u64,
    channel_id: u64,
) -> Result<(), Box<dyn Error>> {
    if channel_id != 0 {
        return Err("the single-share path runs on the q0 channel".into());
    }
    if secret >= N4096_THRESHOLD_MODULI[0] {
        return Err("secret does not fit the q0 threshold domain".into());
    }
    let config = CommitteeConfig::default();
    if sender_id == 0
        || recipient_id == 0
        || sender_id == recipient_id
        || sender_id > config.committee_n as u64
        || recipient_id > config.committee_n as u64
    {
        return Err("sender and recipient IDs must be distinct values in 1..=N".into());
    }

    let mut rng = ark_std::test_rng();
    let mut secret_poly = vec![0u64; N4096_DEGREE];
    secret_poly[0] = secret;
    let sharing = generate_zq_sharing(&secret_poly, &config, &mut rng);

    // Native threshold reconstruction check from the first T q0 shares.
    let q0_shares = sharing
        .shares
        .iter()
        .map(|share| project_channel(share, 0))
        .collect::<Vec<_>>();
    let reconstruction = (0..config.threshold_t)
        .map(|index| (index as u64 + 1, q0_shares[index][0]))
        .collect::<Vec<_>>();
    assert_eq!(
        q0::reconstruct_constant(&reconstruction)?,
        secret % N4096_THRESHOLD_MODULI[0],
        "threshold reconstruction did not recover the secret"
    );

    q0::prove_r2_sharing(&project_channel(&sharing.secret, 0), &q0_shares, &config)?;

    let recipient_share = round_trip_poly_share(&q0_shares[(recipient_id - 1) as usize])?;
    q0::prove_r4_opening(&recipient_share, sender_id, recipient_id, &config)
}

/// Run the full H-dealer committee through one recipient transport key on the
/// q0 channel and fold all metadata-bound R4 openings into one accumulator.
pub fn round_trip_shamir_committee_r4(config: &CommitteeConfig) -> Result<(), Box<dyn Error>> {
    config.validate()?;
    let recipient = config.recipient_id;

    let transport = ShareTransport::new()?;
    let mut sharing_rng = ark_std::test_rng();
    let gen_start = std::time::Instant::now();
    let sharings = (0..config.honest_h as u64)
        .map(|dealer| {
            let mut secret_poly = vec![0u64; N4096_DEGREE];
            secret_poly[0] = 0x1234_0000 + dealer + 1;
            generate_zq_sharing(&secret_poly, config, &mut sharing_rng)
        })
        .collect::<Vec<_>>();
    if std::env::var_os("DKG_PHASE_TIMING").is_some() {
        eprintln!(
            "[gen] {} Z_Q sharings (N={}, T={}): {:.1}s",
            sharings.len(),
            config.committee_n,
            config.threshold_t,
            gen_start.elapsed().as_secs_f64()
        );
    }

    let decoded = q0::fold_committee_r4(&transport, &project_sharings(&sharings, 0), config)?;

    // DKG semantics: the aggregated received shares are a threshold share of
    // the aggregated secret. Reconstruct the aggregate from T aggregated
    // shares of the untransported committee and compare the constant terms.
    let q0_modulus = N4096_THRESHOLD_MODULI[0] as u128;
    let aggregated_secret = sharings
        .iter()
        .fold(0u128, |acc, sharing| (acc + sharing.secret[0]) % q0_modulus)
        as u64
        % N4096_THRESHOLD_MODULI[0];
    let aggregated_shares = (0..config.threshold_t)
        .map(|index| {
            let sum = sharings.iter().fold(0u128, |acc, sharing| {
                (acc + sharing.shares[index][0] % q0_modulus) % q0_modulus
            });
            (index as u64 + 1, sum as u64)
        })
        .collect::<Vec<_>>();
    assert_eq!(
        q0::reconstruct_constant(&aggregated_shares)?,
        aggregated_secret,
        "aggregated threshold reconstruction did not recover the aggregate secret"
    );

    // The transported recipient shares must match the untransported ones.
    for (sharing, decoded_share) in sharings.iter().zip(&decoded) {
        assert_eq!(
            project_channel(&sharing.shares[recipient - 1], 0),
            *decoded_share,
            "BFV transport altered a committee share"
        );
    }

    Ok(())
}

/// Run the H-dealer committee across all three RNS channels: one Z_Q sharing
/// per dealer projected to q0/q1/q2, per-channel R2 proofs, BFV transport,
/// per-channel folded R4 accumulators, and a CRT consistency check that the
/// three transported channel projections recombine to the Z_Q share.
pub fn round_trip_multichannel_committee_r4(
    config: &CommitteeConfig,
) -> Result<(), Box<dyn Error>> {
    config.validate()?;
    let recipient = config.recipient_id;

    let transport = ShareTransport::new()?;
    let mut sharing_rng = ark_std::test_rng();
    let sharings = (0..config.honest_h as u64)
        .map(|dealer| {
            let mut secret_poly = vec![0u64; N4096_DEGREE];
            secret_poly[0] = 0x4321_0000 + dealer + 1;
            generate_zq_sharing(&secret_poly, config, &mut sharing_rng)
        })
        .collect::<Vec<_>>();

    // The three RNS channels share only the read-only sharings and transport,
    // so their (sequential) R4 fold chains are independent. Run them on three
    // threads concurrently — the dominant per-channel cost is the serial fold
    // chain, so this is close to a 3x wall-clock win. Errors are stringified to
    // cross the thread boundary (Box<dyn Error> is not Send).
    let (decoded_q0, decoded_q1, decoded_q2) = std::thread::scope(|scope| {
        let handle_q0 = scope
            .spawn(|| q0::fold_committee_r4(&transport, &project_sharings(&sharings, 0), config).map_err(|e| e.to_string()));
        let handle_q1 = scope
            .spawn(|| q1::fold_committee_r4(&transport, &project_sharings(&sharings, 1), config).map_err(|e| e.to_string()));
        let decoded_q2 = q2::fold_committee_r4(&transport, &project_sharings(&sharings, 2), config).map_err(|e| e.to_string());
        (
            handle_q0.join().unwrap_or_else(|_| Err("q0 fold thread panicked".to_string())),
            handle_q1.join().unwrap_or_else(|_| Err("q1 fold thread panicked".to_string())),
            decoded_q2,
        )
    });
    let decoded_q0 = decoded_q0?;
    let decoded_q1 = decoded_q1?;
    let decoded_q2 = decoded_q2?;

    // CRT consistency: the transported per-channel projections of every
    // dealer share must recombine coefficient-wise to the Z_Q share.
    for (dealer_index, sharing) in sharings.iter().enumerate() {
        let expected = &sharing.shares[recipient - 1];
        for coefficient in 0..N4096_DEGREE {
            let combined = crt_combine([
                decoded_q0[dealer_index][coefficient],
                decoded_q1[dealer_index][coefficient],
                decoded_q2[dealer_index][coefficient],
            ]);
            assert_eq!(
                combined, expected[coefficient],
                "channel projections of dealer {dealer_index} did not recombine at \
                 coefficient {coefficient}"
            );
        }
    }

    // Per-channel aggregated reconstruction, then CRT-combine the aggregate.
    let mut aggregate_residues = [0u64; 3];
    let reconstructors = [
        q0::reconstruct_constant as fn(&[(u64, u64)]) -> Result<u64, Box<dyn Error>>,
        q1::reconstruct_constant,
        q2::reconstruct_constant,
    ];
    for channel in 0..3 {
        let modulus = N4096_THRESHOLD_MODULI[channel] as u128;
        let aggregated_shares = (0..config.threshold_t)
            .map(|index| {
                let sum = sharings.iter().fold(0u128, |acc, sharing| {
                    (acc + sharing.shares[index][0] % modulus) % modulus
                });
                (index as u64 + 1, sum as u64)
            })
            .collect::<Vec<_>>();
        aggregate_residues[channel] = reconstructors[channel](&aggregated_shares)?;
    }
    let aggregated_secret = sharings.iter().fold(0u128, |acc, sharing| {
        (acc + sharing.secret[0]) % N4096_THRESHOLD_MODULUS_PRODUCT
    });
    assert_eq!(
        crt_combine(aggregate_residues),
        aggregated_secret,
        "multi-channel aggregate reconstruction did not recombine to the Z_Q secret"
    );

    Ok(())
}
