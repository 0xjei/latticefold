use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig};
use ark_ff::PrimeField;
use stark_rings::cyclotomic_ring::models::interfold::Fq;

use crate::rings::{GetPoseidonParams, InterfoldPoseidonConfig};

impl GetPoseidonParams<Fq> for InterfoldPoseidonConfig {
    fn get_poseidon_config() -> PoseidonConfig<Fq> {
        // Same sponge geometry as the Goldilocks (64-bit) config: state width
        // 24 = rate 20 + capacity 4, 8 full / 22 partial rounds. α = 7 is the
        // smallest exponent coprime with q − 1 (3 and 5 divide it).
        //
        // The round constants and MDS matrix are generated deterministically
        // with the Grain-LFSR procedure standard for Poseidon instantiations
        // (the same generator ark-crypto-primitives exposes), seeded by the
        // field size and geometry — no hand-derived constants required.
        let full_rounds = 8;
        let partial_rounds = 22;
        let alpha = 7;
        let rate = 20;
        let capacity = 4;

        let (ark, mds) = find_poseidon_ark_and_mds::<Fq>(
            Fq::MODULUS_BIT_SIZE as u64,
            rate + capacity - 1, // LFSR is seeded with state width = rate' + 1
            full_rounds,
            partial_rounds,
            0,
        );

        PoseidonConfig::<Fq>::new(
            full_rounds as usize,
            partial_rounds as usize,
            alpha,
            mds,
            ark,
            rate,
            capacity,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_shape() {
        let config = InterfoldPoseidonConfig::get_poseidon_config();
        assert_eq!(config.rate + config.capacity, 24);
        assert_eq!(config.mds.len(), 24);
        assert_eq!(config.mds[0].len(), 24);
        assert_eq!(config.ark[0].len(), 24);
        assert_eq!(config.full_rounds + config.partial_rounds, 30);
    }
}
