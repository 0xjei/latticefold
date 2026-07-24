use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
use ark_ff::PrimeField;
use stark_rings::cyclotomic_ring::models::n4096::{Fq0, Fq1, Fq2, FqP};

use crate::rings::{
    GetPoseidonParams, N4096PPoseidonConfig, N4096Q0PoseidonConfig, N4096Q1PoseidonConfig,
    N4096Q2PoseidonConfig,
};

fn config<F: PrimeField>() -> PoseidonConfig<F> {
    let full_rounds = 8;
    let partial_rounds = 22;
    let alpha = 5;
    let rate = 20;
    let capacity = 4;

    let (ark, mds) = find_poseidon_ark_and_mds::<F>(
        F::MODULUS_BIT_SIZE as u64,
        rate + capacity - 1,
        full_rounds,
        partial_rounds,
        0,
    );

    PoseidonConfig::new(
        full_rounds as usize,
        partial_rounds as usize,
        alpha,
        mds,
        ark,
        rate,
        capacity,
    )
}

impl GetPoseidonParams<Fq0> for N4096Q0PoseidonConfig {
    fn get_poseidon_config() -> PoseidonConfig<Fq0> {
        config()
    }
}

impl GetPoseidonParams<Fq1> for N4096Q1PoseidonConfig {
    fn get_poseidon_config() -> PoseidonConfig<Fq1> {
        config()
    }
}

impl GetPoseidonParams<Fq2> for N4096Q2PoseidonConfig {
    fn get_poseidon_config() -> PoseidonConfig<Fq2> {
        config()
    }
}

impl GetPoseidonParams<FqP> for N4096PPoseidonConfig {
    fn get_poseidon_config() -> PoseidonConfig<FqP> {
        config()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_shape<F: PrimeField>(config: &PoseidonConfig<F>) {
        assert_eq!(config.rate + config.capacity, 24);
        assert_eq!(config.mds.len(), 24);
        assert_eq!(config.mds[0].len(), 24);
        assert_eq!(config.ark[0].len(), 24);
    }

    #[test]
    fn configs_have_expected_shape() {
        assert_shape(&N4096Q0PoseidonConfig::get_poseidon_config());
        assert_shape(&N4096Q1PoseidonConfig::get_poseidon_config());
        assert_shape(&N4096Q2PoseidonConfig::get_poseidon_config());
    }
}
