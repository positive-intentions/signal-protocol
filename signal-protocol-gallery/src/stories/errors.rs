use dioxus::prelude::*;
use signal_protocol_core::{
    double_ratchet_decrypt_internal, double_ratchet_encrypt_internal, generate_identity_keypair,
    initialize_double_ratchet_internal, sign_data_internal, validate_x25519_public_key,
    verify_signature_internal, x3dh_initiate_internal,
};
use whatsup_ui::components::atoms::BodyText;

use crate::edu::{
    DemoShell, StatusBanner, StatusMsg, StepControls, StepDef, StepHeader, TeachBack,
};

const STEPS: &[StepDef] = &[
    StepDef {
        title: "Bad pubkey",
        why: "X25519 public keys must be 32 bytes. Shorter material is rejected before any ECDH.",
    },
    StepDef {
        title: "X3DH bad prekey",
        why: "Feeding a truncated signed-prekey public key into X3DH should fail key agreement.",
    },
    StepDef {
        title: "DR bad secret",
        why: "Double Ratchet root secrets must be exactly 32 bytes (the X3DH output length).",
    },
    StepDef {
        title: "Tampered CT",
        why: "AEAD authentication detects ciphertext flips — decrypt must fail.",
    },
    StepDef {
        title: "Wrong verify key",
        why: "A signature created with one key must not verify under a different public key.",
    },
];

whatsup_ui::register_gui_story! {
    name: "Error surface",
    group: "Signal Protocol",
    docs: include_str!("errors.md"),
    knobs: [],
    render: |_| {
        rsx! { ErrorSurfaceDemo {} }
    },
}

#[component]
fn ErrorSurfaceDemo() -> Element {
    let mut step = use_signal(|| 0usize);
    let mut teach = use_signal(Vec::<String>::new);
    let mut results = use_signal(Vec::<String>::new);
    let mut status =
        use_signal(|| StatusMsg::info("Press Next to trigger the first intentional failure."));

    let steps: Vec<StepDef> = STEPS.to_vec();
    let current = step();
    let at_end = current >= STEPS.len();

    rsx! {
        DemoShell { title: "Error surface".to_string(),
            StepHeader { steps: steps.clone(), current: current.min(STEPS.len().saturating_sub(1)) }
            StatusBanner { status: status() }
            StepControls {
                can_back: current > 0,
                can_next: !at_end,
                next_label: if at_end { "Done".to_string() } else { "Next failure".to_string() },
                on_back: move |_| {
                    if current == 0 {
                        return;
                    }
                    step.set(current - 1);
                    status.set(StatusMsg::info(format!("Back to: {}", STEPS[current - 1].title)));
                },
                on_next: move |_| {
                    if at_end {
                        return;
                    }
                    match current {
                        0 => {
                            let bad = vec![1u8, 2, 3];
                            let msg = match validate_x25519_public_key(&bad) {
                                Ok(()) => "unexpected Ok".into(),
                                Err(e) => format!("validate_x25519_public_key → {e}"),
                            };
                            teach.write().push(
                                "Reject non-32-byte public key before ECDH".into(),
                            );
                            results.write().push(msg.clone());
                            status.set(StatusMsg::ok(msg));
                        }
                        1 => {
                            let alice = generate_identity_keypair();
                            let eph = generate_identity_keypair();
                            let bob = generate_identity_keypair();
                            let short = vec![0u8; 8];
                            let msg = match x3dh_initiate_internal(
                                &alice.private_key,
                                &eph.private_key,
                                &bob.public_key,
                                &short,
                                None,
                            ) {
                                Ok(_) => "unexpected Ok".into(),
                                Err(e) => format!("x3dh_initiate (short SPK) → {e}"),
                            };
                            teach.write().push(
                                "X3DH cannot ECDH with a truncated SPK public key".into(),
                            );
                            results.write().push(msg.clone());
                            status.set(StatusMsg::ok(msg));
                        }
                        2 => {
                            let msg = match initialize_double_ratchet_internal(&[0u8; 16], true) {
                                Ok(_) => "unexpected Ok".into(),
                                Err(e) => format!("DR init short secret → {e}"),
                            };
                            teach.write().push(
                                "DR root must be 32 bytes (X3DH shared secret length)".into(),
                            );
                            results.write().push(msg.clone());
                            status.set(StatusMsg::ok(msg));
                        }
                        3 => {
                            let root = [7u8; 32];
                            let mut alice = match initialize_double_ratchet_internal(&root, true) {
                                Ok(s) => s,
                                Err(e) => {
                                    status.set(StatusMsg::err(format!("setup failed: {e}")));
                                    return;
                                }
                            };
                            let mut bob = match initialize_double_ratchet_internal(&root, false) {
                                Ok(s) => s,
                                Err(e) => {
                                    status.set(StatusMsg::err(format!("setup failed: {e}")));
                                    return;
                                }
                            };
                            let mut msg =
                                match double_ratchet_encrypt_internal(&mut alice, b"tamper me") {
                                    Ok(m) => m,
                                    Err(e) => {
                                        status.set(StatusMsg::err(format!("encrypt failed: {e}")));
                                        return;
                                    }
                                };
                            if let Some(b) = msg.ciphertext.last_mut() {
                                *b ^= 0xff;
                            }
                            let line = match double_ratchet_decrypt_internal(&mut bob, &msg) {
                                Ok(_) => "unexpected Ok".into(),
                                Err(e) => format!("decrypt tampered → {e}"),
                            };
                            teach.write().push(
                                "Flip one ciphertext byte → AEAD auth failure".into(),
                            );
                            results.write().push(line.clone());
                            status.set(StatusMsg::ok(line));
                        }
                        4 => {
                            let signer = generate_identity_keypair();
                            let other = generate_identity_keypair();
                            let data = b"bundle-signature";
                            let sig = match sign_data_internal(&signer.private_key, data) {
                                Ok(s) => s,
                                Err(e) => {
                                    status.set(StatusMsg::err(format!("sign failed: {e}")));
                                    return;
                                }
                            };
                            let line =
                                match verify_signature_internal(&other.public_key, &sig, data) {
                                    Ok(true) => "unexpected verify true".into(),
                                    Ok(false) => {
                                        "verify returned false (wrong key) — expected".into()
                                    }
                                    Err(e) => format!("verify_signature → {e}"),
                                };
                            teach.write().push(
                                "Signature over data must bind to the signer’s public key".into(),
                            );
                            results.write().push(line.clone());
                            status.set(StatusMsg::ok(line));
                        }
                        _ => {}
                    }
                    step.set(current + 1);
                },
                on_reset: move |_| {
                    step.set(0);
                    teach.set(Vec::new());
                    results.set(Vec::new());
                    status.set(StatusMsg::info(
                        "Press Next to trigger the first intentional failure.",
                    ));
                },
            }
            div { class: "rounded-lg border border-wa-border p-3 dark:border-wa-border-dark",
                p { class: "mb-2 text-sm font-semibold", "Observed errors" }
                if results().is_empty() {
                    BodyText { "No failures recorded yet." }
                } else {
                    ul { class: "list-disc space-y-1 pl-5 font-mono text-xs",
                        for line in results() {
                            li { "{line}" }
                        }
                    }
                }
            }
            TeachBack { entries: teach() }
        }
    }
}
