use dioxus::prelude::*;
use signal_protocol_core::{
    double_ratchet_decrypt_internal, double_ratchet_encrypt_internal, generate_ephemeral_keypair,
    generate_identity_keypair, generate_one_time_prekey, generate_signed_prekey,
    initialize_double_ratchet_internal, x3dh_initiate_internal, x3dh_respond_internal,
    DoubleRatchetState, X3DHResult,
};
use whatsup_ui::gallery::KnobDef;

use crate::edu::{
    DemoShell, MatchChip, StatusBanner, StatusMsg, StepControls, StepDef, StepHeader, TeachBack,
};
use crate::util::hex_preview;

const STEPS: &[StepDef] = &[
    StepDef {
        title: "X3DH",
        why: "Alice and Bob derive one shared secret from the prekey bundle + Alice’s ephemeral.",
    },
    StepDef {
        title: "Init DR",
        why: "That shared secret becomes the Double Ratchet root. Alice initiates; Bob responds.",
    },
    StepDef {
        title: "Alice → Bob",
        why: "First sealed message. Bob’s decrypt installs his receiving chain (DH ratchet).",
    },
    StepDef {
        title: "Bob → Alice",
        why: "Reply in the other direction. Alice ratchets to receive Bob’s sending chain.",
    },
    StepDef {
        title: "Send again",
        why: "Messaging phase: another Alice→Bob then Bob→Alice round using the Controls texts.",
    },
];

whatsup_ui::register_gui_story! {
    name: "Full session",
    group: "Signal Protocol",
    docs: include_str!("full_session.md"),
    knobs: [
        KnobDef::text("alice_msg", "Alice message", "Hi Bob — sealed with Signal."),
        KnobDef::text("bob_msg", "Bob message", "Hey Alice — ratchet works."),
    ],
    render: |k| {
        let alice_msg = k.get_str("alice_msg").to_string();
        let bob_msg = k.get_str("bob_msg").to_string();
        rsx! { FullSessionDemo { alice_msg, bob_msg } }
    },
}

#[derive(Clone)]
struct TranscriptLine {
    from: &'static str,
    text: String,
}

#[derive(Clone, Default)]
struct FullSession {
    alice: Option<DoubleRatchetState>,
    bob: Option<DoubleRatchetState>,
    x3dh: Option<X3DHResult>,
    transcript: Vec<TranscriptLine>,
}

#[component]
fn FullSessionDemo(alice_msg: String, bob_msg: String) -> Element {
    let mut step = use_signal(|| 0usize);
    let mut session = use_signal(FullSession::default);
    let mut teach = use_signal(Vec::<String>::new);
    let mut status = use_signal(|| StatusMsg::info("Press Next to run X3DH."));

    let steps: Vec<StepDef> = STEPS.to_vec();
    let current = step();
    let at_end = current >= STEPS.len();
    let phase = if current <= 1 {
        "Handshake"
    } else {
        "Messaging"
    };
    let secrets_ok = session().x3dh.is_some();

    rsx! {
        DemoShell { title: "Full session".to_string(),
            StepHeader { steps: steps.clone(), current: current.min(STEPS.len().saturating_sub(1)) }
            div { class: "flex flex-wrap items-center gap-2",
                span { class: "rounded-full border border-wa-border px-3 py-1 text-xs font-bold dark:border-wa-border-dark",
                    "Phase: {phase}"
                }
                MatchChip { label: "X3DH ready".to_string(), matched: Some(secrets_ok) }
            }
            StatusBanner { status: status() }
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
                            let alice_id = generate_identity_keypair();
                            let alice_eph = generate_ephemeral_keypair();
                            let bob_id = generate_identity_keypair();
                            let bob_spk = generate_signed_prekey();
                            let bob_otpk = generate_one_time_prekey();
                            let alice_x3dh = match x3dh_initiate_internal(
                                &alice_id.private_key,
                                &alice_eph.private_key,
                                &bob_id.public_key,
                                &bob_spk.public_key,
                                Some(&bob_otpk.public_key),
                            ) {
                                Ok(r) => r,
                                Err(e) => {
                                    status.set(StatusMsg::err(format!("x3dh initiate: {e}")));
                                    return;
                                }
                            };
                            let bob_x3dh = match x3dh_respond_internal(
                                &bob_id.private_key,
                                &bob_spk.private_key,
                                Some(&bob_otpk.private_key),
                                &alice_id.public_key,
                                &alice_eph.public_key,
                            ) {
                                Ok(r) => r,
                                Err(e) => {
                                    status.set(StatusMsg::err(format!("x3dh respond: {e}")));
                                    return;
                                }
                            };
                            if alice_x3dh.shared_secret != bob_x3dh.shared_secret {
                                status.set(StatusMsg::err("X3DH shared secret mismatch"));
                                return;
                            }
                            teach.write().push(format!(
                                "X3DH OK shared={}",
                                hex_preview(&alice_x3dh.shared_secret, 16)
                            ));
                            session.write().x3dh = Some(alice_x3dh.clone());
                            session.write().transcript.push(TranscriptLine {
                                from: "system",
                                text: format!(
                                    "X3DH complete ({})",
                                    hex_preview(&alice_x3dh.shared_secret, 16)
                                ),
                            });
                            status.set(StatusMsg::ok("X3DH secrets match."));
                        }
                        1 => {
                            let Some(x3dh) = session().x3dh.clone() else {
                                status.set(StatusMsg::err("Run X3DH first."));
                                return;
                            };
                            let alice = match initialize_double_ratchet_internal(
                                &x3dh.shared_secret,
                                true,
                            ) {
                                Ok(s) => s,
                                Err(e) => {
                                    status.set(StatusMsg::err(e.to_string()));
                                    return;
                                }
                            };
                            let bob = match initialize_double_ratchet_internal(
                                &x3dh.shared_secret,
                                false,
                            ) {
                                Ok(s) => s,
                                Err(e) => {
                                    status.set(StatusMsg::err(e.to_string()));
                                    return;
                                }
                            };
                            session.write().alice = Some(alice);
                            session.write().bob = Some(bob);
                            session.write().transcript.push(TranscriptLine {
                                from: "system",
                                text: "Double Ratchet ready — messaging can begin".into(),
                            });
                            teach.write().push("DR init (Alice initiator, Bob responder)".into());
                            status.set(StatusMsg::ok("Ratchet initialized."));
                        }
                        2 | 4 => {
                            let mut s = session();
                            let (Some(alice), Some(bob)) = (s.alice.as_mut(), s.bob.as_mut()) else {
                                status.set(StatusMsg::err("Init DR first."));
                                return;
                            };
                            let msg = match double_ratchet_encrypt_internal(
                                alice,
                                alice_msg.as_bytes(),
                            ) {
                                Ok(m) => m,
                                Err(e) => {
                                    status.set(StatusMsg::err(e.to_string()));
                                    return;
                                }
                            };
                            match double_ratchet_decrypt_internal(bob, &msg) {
                                Ok(pt) => {
                                    let text = String::from_utf8_lossy(&pt).to_string();
                                    s.transcript.push(TranscriptLine {
                                        from: "Alice",
                                        text: text.clone(),
                                    });
                                    session.set(s);
                                    teach.write().push(format!("Alice → Bob: {text}"));
                                    status.set(StatusMsg::ok("Alice message delivered."));
                                }
                                Err(e) => {
                                    status.set(StatusMsg::err(e.to_string()));
                                    return;
                                }
                            }
                        }
                        3 => {
                            let mut s = session();
                            let (Some(alice), Some(bob)) = (s.alice.as_mut(), s.bob.as_mut()) else {
                                status.set(StatusMsg::err("Init DR first."));
                                return;
                            };
                            let msg = match double_ratchet_encrypt_internal(bob, bob_msg.as_bytes())
                            {
                                Ok(m) => m,
                                Err(e) => {
                                    status.set(StatusMsg::err(e.to_string()));
                                    return;
                                }
                            };
                            match double_ratchet_decrypt_internal(alice, &msg) {
                                Ok(pt) => {
                                    let text = String::from_utf8_lossy(&pt).to_string();
                                    s.transcript.push(TranscriptLine {
                                        from: "Bob",
                                        text: text.clone(),
                                    });
                                    session.set(s);
                                    teach.write().push(format!("Bob → Alice: {text}"));
                                    status.set(StatusMsg::ok("Bob reply delivered."));
                                }
                                Err(e) => {
                                    status.set(StatusMsg::err(e.to_string()));
                                    return;
                                }
                            }
                        }
                        _ => {}
                    }
                    // Step 4 also sends Bob→Alice after Alice→Bob
                    if current == 4 {
                        let mut s = session();
                        if let (Some(alice), Some(bob)) = (s.alice.as_mut(), s.bob.as_mut()) {
                            if let Ok(msg) =
                                double_ratchet_encrypt_internal(bob, bob_msg.as_bytes())
                            {
                                if let Ok(pt) = double_ratchet_decrypt_internal(alice, &msg) {
                                    let text = String::from_utf8_lossy(&pt).to_string();
                                    s.transcript.push(TranscriptLine {
                                        from: "Bob",
                                        text: text.clone(),
                                    });
                                    teach.write().push(format!("Bob → Alice (again): {text}"));
                                    session.set(s);
                                }
                            }
                        }
                    }
                    step.set(current + 1);
                },
                on_reset: move |_| {
                    step.set(0);
                    session.set(FullSession::default());
                    teach.set(Vec::new());
                    status.set(StatusMsg::info("Press Next to run X3DH."));
                },
            }
            div { class: "flex flex-col gap-2 rounded-xl bg-[#ece5dd] p-3 dark:bg-[#0b141a]",
                for line in session().transcript {
                    {
                        let bubble_class = if line.from == "Alice" {
                            "ml-auto max-w-[80%] rounded-lg bg-[#dcf8c6] px-3 py-2 text-sm text-wa-ink"
                        } else if line.from == "Bob" {
                            "mr-auto max-w-[80%] rounded-lg bg-white px-3 py-2 text-sm text-wa-ink dark:bg-wa-panel-dark dark:text-wa-ink-dark"
                        } else {
                            "mx-auto rounded-lg bg-wa-header/80 px-3 py-1 text-xs text-wa-muted"
                        };
                        let from = line.from;
                        let text = line.text.clone();
                        rsx! {
                            div { class: "{bubble_class}",
                                if from == "system" {
                                    "{text}"
                                } else {
                                    span { class: "font-semibold", "{from}: " }
                                    "{text}"
                                }
                            }
                        }
                    }
                }
            }
            TeachBack { entries: teach() }
        }
    }
}
