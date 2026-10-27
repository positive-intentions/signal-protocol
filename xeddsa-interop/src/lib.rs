//! Interop tests: our `signal_protocol_core::xeddsa_*` vs the Signal XEdDSA
//! reference crate (`xeddsa` on crates.io). Checked-in vectors in `vectors.json`.

#![cfg(test)]

use rand::{rngs::StdRng, SeedableRng};
use signal_protocol_core::{montgomery_to_edwards_public, xeddsa_sign, xeddsa_verify};
use x25519_dalek::{PublicKey, StaticSecret};
use xeddsa::xed25519::{PrivateKey as RefPrivate, PublicKey as RefPublic};
use xeddsa::{Sign, Verify};

fn random_kp(seed_byte: u8) -> (StaticSecret, PublicKey, StdRng) {
    let mut seed = [0u8; 32];
    seed[0] = seed_byte;
    seed[2] = 0xAB;
    let sk = StaticSecret::from(seed);
    let pk = PublicKey::from(&sk);
    let mut rng_seed = [3u8; 32];
    rng_seed[0] = seed_byte;
    let rng = StdRng::from_seed(rng_seed);
    (sk, pk, rng)
}

#[test]
fn our_sign_ref_verify() {
    let (sk, pk, _) = random_kp(1);
    let msg = b"interop our->ref";
    let sig = xeddsa_sign(sk.as_bytes(), msg).expect("sign");
    let ref_pk = RefPublic::from(&pk);
    let sig_arr: [u8; 64] = sig.as_slice().try_into().unwrap();
    ref_pk
        .verify(msg, &sig_arr)
        .expect("ref must verify our signature");
}

#[test]
fn ref_sign_our_verify() {
    let (sk, pk, mut rng) = random_kp(2);
    let msg = b"interop ref->our";
    let ref_sk = RefPrivate::from(&sk);
    let sig = Sign::<[u8; 64], _, _>::sign(&ref_sk, msg, &mut rng);
    assert!(
        xeddsa_verify(pk.as_bytes(), &sig, msg).unwrap(),
        "ours must verify ref signature"
    );
}

#[test]
fn edwards_conversion_sign_bit_clear() {
    let (_sk, pk, _) = random_kp(3);
    let ours = montgomery_to_edwards_public(pk.as_bytes()).unwrap();
    assert_eq!(ours[31] & 0x80, 0);
    let _ = RefPublic::from(&pk);
}

#[test]
fn negative_tampered_message() {
    let (sk, pk, _) = random_kp(4);
    let sig = xeddsa_sign(sk.as_bytes(), b"good").unwrap();
    assert!(!xeddsa_verify(pk.as_bytes(), &sig, b"bad").unwrap());
}

#[test]
fn checked_in_vectors_replay() {
    let raw = include_str!("../vectors.json");
    let vectors: Vec<Vector> = serde_json::from_str(raw).expect("vectors.json");
    assert!(!vectors.is_empty());
    for v in vectors {
        let sk: [u8; 32] = hex::decode(&v.private_key)
            .unwrap()
            .try_into()
            .unwrap();
        let pk: [u8; 32] = hex::decode(&v.public_key).unwrap().try_into().unwrap();
        let msg = hex::decode(&v.message).unwrap();
        let sig = hex::decode(&v.signature).unwrap();
        assert!(
            xeddsa_verify(&pk, &sig, &msg).unwrap(),
            "vector {} must verify",
            v.name
        );
        let ours = xeddsa_sign(&sk, &msg).unwrap();
        assert!(xeddsa_verify(&pk, &ours, &msg).unwrap());
    }
}

#[test]
fn excess_bits_rejected() {
    let (sk, pk, _) = random_kp(5);
    let mut sig = xeddsa_sign(sk.as_bytes(), b"m").unwrap();
    sig[63] |= 0xe0;
    assert!(!xeddsa_verify(pk.as_bytes(), &sig, b"m").unwrap());
}

#[derive(serde::Deserialize)]
struct Vector {
    name: String,
    private_key: String,
    public_key: String,
    message: String,
    signature: String,
}
