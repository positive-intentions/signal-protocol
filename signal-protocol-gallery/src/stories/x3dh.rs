use dioxus::prelude::*;
use signal_protocol_core::{
    generate_ephemeral_keypair, generate_identity_keypair, generate_one_time_prekey,
    generate_signed_prekey, x3dh_initiate_internal, x3dh_respond_internal, KeyPair, X3DHResult,
};
use whatsup_ui::gallery::KnobDef;

use crate::edu::{
    DemoShell, LabeledBytes, MatchChip, PartyPanel, PrivateToggle, StatusBanner, StatusMsg,
    StepControls, StepDef, StepHeader, TeachBack,
};
use crate::util::hex_preview;

const STEPS: &[StepDef] = &[
    StepDef {
        title: "Alice keys",
        why: "Alice needs a long-term identity and a fresh ephemeral key that will never be reused.",
    },
    StepDef {
        title: "Bob bundle",
        why: "Bob publishes identity + signed prekey (+ optional one-time prekey) so Alice can start a session offline.",
    },
    StepDef {
        title: "Alice initiate",
        why: "Alice runs ECDH combinations (DH1–DH3/DH4) and HKDF to derive the shared secret.",
    },
    StepDef {
        title: "Bob respond",
        why: "Bob runs the mirror ECDHs with his private keys and Alice’s public ephemeral/identity.",
    },
    StepDef {
        title: "Compare",
        why: "Both sides must obtain identical shared_secret and associated_data — that is the handshake success.",
    },
];

whatsup_ui::register_gui_story! {
    name: "X3DH handshake",
    group: "Signal Protocol",
    docs: include_str!("x3dh.md"),
    knobs: [
        KnobDef::bool("use_otpk", "Use one-time prekey", true),
    ],
    render: |k| {
        let use_otpk = k.get_bool("use_otpk");
        rsx! { X3dhDemo { use_otpk } }
    },
}

#[derive(Clone, Default)]
struct Parties {
    alice_id: Option<KeyPair>,
    alice_eph: Option<KeyPair>,
    bob_id: Option<KeyPair>,
    bob_spk: Option<KeyPair>,
    bob_otpk: Option<KeyPair>,
    alice_result: Option<X3DHResult>,
    bob_result: Option<X3DHResult>,
}

#[component]
fn X3dhDemo(use_otpk: bool) -> Element {
    let mut step = use_signal(|| 0usize);
    let mut parties = use_signal(Parties::default);
    let mut teach = use_signal(Vec::<String>::new);
    let mut status = use_signal(|| {
        StatusMsg::info(format!(
            "OTPK {}: press Next to generate Alice’s keys.",
            if use_otpk { "enabled" } else { "disabled" }
        ))
    });
    let mut show_private = use_signal(|| false);

    let steps: Vec<StepDef> = STEPS.to_vec();
    let current = step();
    let at_end = current >= STEPS.len();
    let p = parties();
    let secrets_match = match (&p.alice_result, &p.bob_result) {
        (Some(a), Some(b)) => {
            Some(a.shared_secret == b.shared_secret && a.associated_data == b.associated_data)
        }
        _ => None,
    };

    rsx! {
        DemoShell { title: "X3DH handshake".to_string(),
            StepHeader { steps: steps.clone(), current: current.min(STEPS.len().saturating_sub(1)) }
            StatusBanner { status: status() }
            div { class: "flex flex-wrap items-center gap-2",
                MatchChip { label: "Secrets match".to_string(), matched: secrets_match }
                MatchChip {
                    label: "OTPK used".to_string(),
                    matched: Some(use_otpk),
                }
            }
            StepControls {
                can_back: current > 0,
                can_next: !at_end,
                next_label: if at_end { "Done".to_string() } else { "Next".to_string() },
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
                            parties.write().alice_id = Some(generate_identity_keypair());
                            parties.write().alice_eph = Some(generate_ephemeral_keypair());
                            teach.write().push("Alice: identity + ephemeral generated".into());
                            status.set(StatusMsg::ok("Alice’s keys ready."));
                        }
                        1 => {
                            parties.write().bob_id = Some(generate_identity_keypair());
                            parties.write().bob_spk = Some(generate_signed_prekey());
                            parties.write().bob_otpk = if use_otpk {
                                Some(generate_one_time_prekey())
                            } else {
                                None
                            };
                            teach.write().push(if use_otpk {
                                "Bob bundle: identity + SPK + OTPK published".into()
                            } else {
                                "Bob bundle: identity + SPK (no OTPK) published".into()
                            });
                            status.set(StatusMsg::ok("Bob’s prekey bundle ready."));
                        }
                        2 => {
                            let p = parties();
                            let (Some(alice_id), Some(alice_eph), Some(bob_id), Some(bob_spk)) = (
                                p.alice_id.as_ref(),
                                p.alice_eph.as_ref(),
                                p.bob_id.as_ref(),
                                p.bob_spk.as_ref(),
                            ) else {
                                status.set(StatusMsg::err("Generate keys first."));
                                return;
                            };
                            let otpk_pub = p.bob_otpk.as_ref().map(|k| k.public_key.as_slice());
                            match x3dh_initiate_internal(
                                &alice_id.private_key,
                                &alice_eph.private_key,
                                &bob_id.public_key,
                                &bob_spk.public_key,
                                otpk_pub,
                            ) {
                                Ok(r) => {
                                    teach.write().push(
                                        "DH1=ECDH(AliceIK_priv, BobSPK_pub)".into(),
                                    );
                                    teach.write().push(
                                        "DH2=ECDH(AliceEK_priv, BobIK_pub)".into(),
                                    );
                                    teach.write().push(
                                        "DH3=ECDH(AliceEK_priv, BobSPK_pub)".into(),
                                    );
                                    if use_otpk {
                                        teach.write().push(
                                            "DH4=ECDH(AliceEK_priv, BobOTPK_pub)".into(),
                                        );
                                    }
                                    teach.write().push(format!(
                                        "HKDF → Alice shared_secret={}",
                                        hex_preview(&r.shared_secret, 24)
                                    ));
                                    parties.write().alice_result = Some(r);
                                    status.set(StatusMsg::ok("Alice derived the shared secret."));
                                }
                                Err(e) => {
                                    status.set(StatusMsg::err(format!("initiate: {e}")));
                                    return;
                                }
                            }
                        }
                        3 => {
                            let p = parties();
                            let (Some(alice_id), Some(alice_eph), Some(bob_id), Some(bob_spk)) = (
                                p.alice_id.as_ref(),
                                p.alice_eph.as_ref(),
                                p.bob_id.as_ref(),
                                p.bob_spk.as_ref(),
                            ) else {
                                status.set(StatusMsg::err("Generate keys first."));
                                return;
                            };
                            let otpk_priv = p.bob_otpk.as_ref().map(|k| k.private_key.as_slice());
                            match x3dh_respond_internal(
                                &bob_id.private_key,
                                &bob_spk.private_key,
                                otpk_priv,
                                &alice_id.public_key,
                                &alice_eph.public_key,
                            ) {
                                Ok(r) => {
                                    teach.write().push(
                                        "Bob mirror ECDHs + HKDF → Bob shared_secret".into(),
                                    );
                                    teach.write().push(format!(
                                        "Bob shared_secret={}",
                                        hex_preview(&r.shared_secret, 24)
                                    ));
                                    parties.write().bob_result = Some(r);
                                    status.set(StatusMsg::ok("Bob derived the shared secret."));
                                }
                                Err(e) => {
                                    status.set(StatusMsg::err(format!("respond: {e}")));
                                    return;
                                }
                            }
                        }
                        4 => {
                            let p = parties();
                            match (&p.alice_result, &p.bob_result) {
                                (Some(a), Some(b))
                                    if a.shared_secret == b.shared_secret
                                        && a.associated_data == b.associated_data =>
                                {
                                    teach.write().push(
                                        "Compare: shared_secret and AD match on both sides".into(),
                                    );
                                    status.set(StatusMsg::ok(
                                        "Handshake success — identical secrets.",
                                    ));
                                }
                                (Some(_), Some(_)) => {
                                    status.set(StatusMsg::err("Secrets did not match."));
                                    return;
                                }
                                _ => {
                                    status.set(StatusMsg::err("Run initiate and respond first."));
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
                    parties.set(Parties::default());
                    teach.set(Vec::new());
                    status.set(StatusMsg::info(format!(
                        "OTPK {}: press Next to generate Alice’s keys.",
                        if use_otpk { "enabled" } else { "disabled" }
                    )));
                },
            }
            PrivateToggle {
                show: show_private(),
                on_toggle: move |v| show_private.set(v),
            }
            div { class: "flex flex-col gap-3 lg:flex-row",
                PartyPanel {
                    name: "Alice".to_string(),
                    role: "Initiator".to_string(),
                    accent: "bg-sky-600".to_string(),
                    show_private: show_private(),
                    fields: vec![
                        LabeledBytes {
                            label: "Identity (public)".to_string(),
                            bytes: p.alice_id.as_ref().map(|k| k.public_key.clone()),
                            is_private: false,
                        },
                        LabeledBytes {
                            label: "Identity (private)".to_string(),
                            bytes: p.alice_id.as_ref().map(|k| k.private_key.clone()),
                            is_private: true,
                        },
                        LabeledBytes {
                            label: "Ephemeral (public)".to_string(),
                            bytes: p.alice_eph.as_ref().map(|k| k.public_key.clone()),
                            is_private: false,
                        },
                        LabeledBytes {
                            label: "Shared secret".to_string(),
                            bytes: p.alice_result.as_ref().map(|r| r.shared_secret.clone()),
                            is_private: false,
                        },
                    ],
                }
                PartyPanel {
                    name: "Bob".to_string(),
                    role: "Responder".to_string(),
                    accent: "bg-emerald-600".to_string(),
                    show_private: show_private(),
                    fields: vec![
                        LabeledBytes {
                            label: "Identity (public)".to_string(),
                            bytes: p.bob_id.as_ref().map(|k| k.public_key.clone()),
                            is_private: false,
                        },
                        LabeledBytes {
                            label: "Signed prekey (public)".to_string(),
                            bytes: p.bob_spk.as_ref().map(|k| k.public_key.clone()),
                            is_private: false,
                        },
                        LabeledBytes {
                            label: "One-time prekey (public)".to_string(),
                            bytes: p.bob_otpk.as_ref().map(|k| k.public_key.clone()),
                            is_private: false,
                        },
                        LabeledBytes {
                            label: "Shared secret".to_string(),
                            bytes: p.bob_result.as_ref().map(|r| r.shared_secret.clone()),
                            is_private: false,
                        },
                    ],
                }
            }
            TeachBack { entries: teach() }
        }
    }
}
