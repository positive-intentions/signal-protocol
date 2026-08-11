use dioxus::prelude::*;
use signal_protocol_core::{
    generate_ephemeral_keypair, generate_identity_keypair, generate_one_time_prekey,
    generate_signed_prekey, validate_x25519_public_key, KeyPair,
};

use crate::edu::{
    DemoShell, HexField, PrivateToggle, StatusBanner, StatusMsg, StepControls, StepDef, StepHeader,
    TeachBack,
};

const STEPS: &[StepDef] = &[
    StepDef {
        title: "Identity",
        why: "Long-term identity key. The public half goes in directories; the private half never leaves the device.",
    },
    StepDef {
        title: "Signed prekey",
        why: "Medium-term prekey Bob publishes and rotates. Alice uses it in X3DH even when Bob is offline.",
    },
    StepDef {
        title: "One-time prekey",
        why: "Single-use prekey. Consuming one adds an extra DH for stronger forward secrecy.",
    },
    StepDef {
        title: "Ephemeral",
        why: "Alice’s one-handshake key. Fresh every session; never reused.",
    },
    StepDef {
        title: "Validate",
        why: "Sanity-check that the identity public key is a valid X25519 point before using it in a protocol.",
    },
];

whatsup_ui::register_gui_story! {
    name: "Key generation",
    group: "Signal Protocol",
    docs: include_str!("keys.md"),
    knobs: [],
    render: |_| {
        rsx! { KeyGenerationDemo {} }
    },
}

#[derive(Clone, Default)]
struct KeyBundle {
    identity: Option<KeyPair>,
    signed_prekey: Option<KeyPair>,
    one_time: Option<KeyPair>,
    ephemeral: Option<KeyPair>,
}

#[component]
fn KeyGenerationDemo() -> Element {
    let mut step = use_signal(|| 0usize);
    let mut bundle = use_signal(KeyBundle::default);
    let mut teach = use_signal(Vec::<String>::new);
    let mut status = use_signal(|| StatusMsg::info("Press Next to generate the identity key."));
    let mut show_private = use_signal(|| false);

    let steps: Vec<StepDef> = STEPS.to_vec();
    let current = step();
    let at_end = current >= STEPS.len();

    rsx! {
        DemoShell { title: "Key generation".to_string(),
            StepHeader { steps: steps.clone(), current: current.min(STEPS.len().saturating_sub(1)) }
            StatusBanner { status: status() }
            StepControls {
                can_back: current > 0,
                can_next: !at_end,
                next_label: if at_end { "Done".to_string() } else { "Next".to_string() },
                on_back: move |_| {
                    if current == 0 {
                        return;
                    }
                    let prev = current - 1;
                    step.set(prev);
                    status.set(StatusMsg::info(format!("Back to step {}: {}", prev + 1, STEPS[prev].title)));
                },
                on_next: move |_| {
                    if at_end {
                        return;
                    }
                    match current {
                        0 => {
                            let kp = generate_identity_keypair();
                            bundle.write().identity = Some(kp);
                            teach.write().push(
                                "generate_identity_keypair() → long-term X25519 identity".into(),
                            );
                            status.set(StatusMsg::ok("Identity key created."));
                        }
                        1 => {
                            let kp = generate_signed_prekey();
                            bundle.write().signed_prekey = Some(kp);
                            teach.write().push(
                                "generate_signed_prekey() → medium-term SPK for Bob’s bundle".into(),
                            );
                            status.set(StatusMsg::ok("Signed prekey created."));
                        }
                        2 => {
                            let kp = generate_one_time_prekey();
                            bundle.write().one_time = Some(kp);
                            teach.write().push(
                                "generate_one_time_prekey() → disposable OTPK (optional in X3DH)".into(),
                            );
                            status.set(StatusMsg::ok("One-time prekey created."));
                        }
                        3 => {
                            let kp = generate_ephemeral_keypair();
                            bundle.write().ephemeral = Some(kp);
                            teach.write().push(
                                "generate_ephemeral_keypair() → Alice’s per-handshake ephemeral".into(),
                            );
                            status.set(StatusMsg::ok("Ephemeral key created."));
                        }
                        4 => {
                            let Some(id) = bundle().identity else {
                                status.set(StatusMsg::err("Missing identity key."));
                                return;
                            };
                            match validate_x25519_public_key(&id.public_key) {
                                Ok(()) => {
                                    teach.write().push(
                                        "validate_x25519_public_key(identity.pub) → Ok".into(),
                                    );
                                    status.set(StatusMsg::ok(
                                        "Identity public key is a valid X25519 key.",
                                    ));
                                }
                                Err(e) => {
                                    status.set(StatusMsg::err(e.to_string()));
                                    return;
                                }
                            }
                        }
                        _ => {}
                    }
                    step.set(current + 1);
                },
                on_reset: move |_| {
                    step.set(0);
                    bundle.set(KeyBundle::default());
                    teach.set(Vec::new());
                    status.set(StatusMsg::info("Press Next to generate the identity key."));
                },
            }
            PrivateToggle {
                show: show_private(),
                on_toggle: move |v| show_private.set(v),
            }
            div { class: "grid gap-3 md:grid-cols-2",
                {
                    let b = bundle();
                    rsx! {
                        KeyCard {
                            title: "Identity".to_string(),
                            pub_bytes: b.identity.as_ref().map(|k| k.public_key.clone()),
                            priv_bytes: b.identity.as_ref().map(|k| k.private_key.clone()),
                            show_private: show_private(),
                        }
                        KeyCard {
                            title: "Signed prekey".to_string(),
                            pub_bytes: b.signed_prekey.as_ref().map(|k| k.public_key.clone()),
                            priv_bytes: b.signed_prekey.as_ref().map(|k| k.private_key.clone()),
                            show_private: show_private(),
                        }
                        KeyCard {
                            title: "One-time prekey".to_string(),
                            pub_bytes: b.one_time.as_ref().map(|k| k.public_key.clone()),
                            priv_bytes: b.one_time.as_ref().map(|k| k.private_key.clone()),
                            show_private: show_private(),
                        }
                        KeyCard {
                            title: "Ephemeral".to_string(),
                            pub_bytes: b.ephemeral.as_ref().map(|k| k.public_key.clone()),
                            priv_bytes: b.ephemeral.as_ref().map(|k| k.private_key.clone()),
                            show_private: show_private(),
                        }
                    }
                }
            }
            TeachBack { entries: teach() }
        }
    }
}

#[component]
fn KeyCard(
    title: String,
    pub_bytes: Option<Vec<u8>>,
    priv_bytes: Option<Vec<u8>>,
    show_private: bool,
) -> Element {
    rsx! {
        div { class: "space-y-2 rounded-lg border border-wa-border p-3 dark:border-wa-border-dark",
            p { class: "font-semibold text-wa-ink dark:text-wa-ink-dark", "{title}" }
            HexField {
                label: "Public".to_string(),
                bytes: pub_bytes,
                show_private: true,
                is_private: false,
            }
            HexField {
                label: "Private".to_string(),
                bytes: priv_bytes,
                show_private,
                is_private: true,
            }
        }
    }
}
