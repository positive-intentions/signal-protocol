//! Generate checked-in XEdDSA vectors using the Signal reference crate.

use rand::{rngs::StdRng, SeedableRng};
use x25519_dalek::{PublicKey, StaticSecret};
use xeddsa::xed25519::PrivateKey as RefPrivate;
use xeddsa::Sign;

fn main() {
    let mut vectors = Vec::new();
    for i in 0..4u8 {
        let mut seed = [0u8; 32];
        seed[0] = i;
        seed[1] = 0x42;
        let sk = StaticSecret::from(seed);
        let pk = PublicKey::from(&sk);
        let msg = format!("vector-{i}-message").into_bytes();
        let ref_sk = RefPrivate::from(&sk);
        let mut rng_seed = [9u8; 32];
        rng_seed[0] = i;
        let mut rng = StdRng::from_seed(rng_seed);
        let sig = Sign::<[u8; 64], _, _>::sign(&ref_sk, &msg, &mut rng);
        vectors.push(serde_json::json!({
            "name": format!("vec-{i}"),
            "private_key": hex::encode(sk.as_bytes()),
            "public_key": hex::encode(pk.as_bytes()),
            "message": hex::encode(&msg),
            "signature": hex::encode(sig),
        }));
    }
    println!("{}", serde_json::to_string_pretty(&vectors).unwrap());
}
