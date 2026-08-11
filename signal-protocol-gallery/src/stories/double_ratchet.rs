use dioxus::prelude::*;
use signal_protocol_core::{
    double_ratchet_decrypt_internal, double_ratchet_encrypt_internal,
    initialize_double_ratchet_internal, DoubleRatchetMessage, DoubleRatchetState,
};
use whatsup_ui::components::atoms::BodyText;
use whatsup_ui::gallery::KnobDef;

use crate::edu::{
    CounterCard, DemoShell, StatusBanner, StatusMsg, StepControls, StepDef, StepHeader, TeachBack,
};
use crate::util::hex_preview;

const STEPS: &[StepDef] = &[
    StepDef {
        title: "Init session",
        why: "Both sides load the same 32-byte root secret. Alice (initiator) starts with a sending chain; Bob waits for the first message.",
    },
    StepDef {
        title: "Alice encrypt",
        why: "Alice derives a message key from her sending chain, AEAD-encrypts the plaintext, and advances the chain.",
    },
    StepDef {
        title: "Bob decrypt",
        why: "Bob’s first decrypt performs a DH ratchet, installs a receiving chain, then decrypts message 0.",
    },
    StepDef {
        title: "Bob encrypt reply",
        why: "After ratcheting, Bob has a sending chain and can encrypt in the reverse direction.",
    },
    StepDef {
        title: "Alice decrypt",
        why: "Alice DH-ratchets to Bob’s new public key and decrypts the reply — forward secrecy across turns.",
    },
];

whatsup_ui::register_gui_story! {
    name: "Double Ratchet playground",
    group: "Signal Protocol",
    docs: include_str!("double_ratchet.md"),
    knobs: [
        KnobDef::text("plaintext", "Plaintext", "hello from Alice"),
    ],
    render: |k| {
        let plaintext = k.get_str("plaintext").to_string();
        rsx! { DoubleRatchetDemo { plaintext } }
    },
}

#[derive(Clone, Default)]
struct Session {
    alice: Option<DoubleRatchetState>,
    bob: Option<DoubleRatchetState>,
    last_ciphertext: Option<DoubleRatchetMessage>,
    last_plaintext: Option<String>,
}

fn chain_flag(v: bool) -> String {
    if v { "yes".into() } else { "no".into() }
}

fn counter_props(st: &Option<DoubleRatchetState>) -> (String, String, String, String, String) {
    match st {
        Some(s) => (
            s.sending_message_number.to_string(),
            s.receiving_message_number.to_string(),
            s.skipped_message_keys.len().to_string(),
            chain_flag(s.sending_chain_key.is_some()),
            chain_flag(s.receiving_chain_key.is_some()),
        ),
        None => ("—".into(), "—".into(), "—".into(), "—".into(), "—".into()),
    }
}

#[component]
fn DoubleRatchetDemo(plaintext: String) -> Element {
    let mut step = use_signal(|| 0usize);
    let mut session = use_signal(Session::default);
    let mut teach = use_signal(Vec::<String>::new);
    let mut status =
        use_signal(|| StatusMsg::info("Press Next to initialize Alice and Bob’s ratchet states."));

    let steps: Vec<StepDef> = STEPS.to_vec();
    let current = step();
    let at_end = current >= STEPS.len();
    let s = session();
    let (a_send, a_recv, a_skip, a_sc, a_rc) = counter_props(&s.alice);
    let (b_send, b_recv, b_skip, b_sc, b_rc) = counter_props(&s.bob);

    rsx! {
        DemoShell { title: "Double Ratchet playground".to_string(),
            StepHeader { steps: steps.clone(), current: current.min(STEPS.len().saturating_sub(1)) }
            BodyText { "Controls plaintext: {plaintext}" }
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
                            let mut root = [0u8; 32];
                            root[0] = 0x42;
                            root[31] = 0x24;
                            match (
                                initialize_double_ratchet_internal(&root, true),
                                initialize_double_ratchet_internal(&root, false),
                            ) {
                                (Ok(alice), Ok(bob)) => {
                                    session.set(Session {
                                        alice: Some(alice),
                                        bob: Some(bob),
                                        last_ciphertext: None,
                                        last_plaintext: None,
                                    });
                                    teach.write().push(
                                        "initialize_double_ratchet(shared, initiator=true) → Alice".into(),
                                    );
                                    teach.write().push(
                                        "initialize_double_ratchet(shared, initiator=false) → Bob".into(),
                                    );
                                    status.set(StatusMsg::ok("Session initialized."));
                                }
                                (Err(e), _) | (_, Err(e)) => {
                                    status.set(StatusMsg::err(e.to_string()));
                                    return;
                                }
                            }
                        }
                        1 => {
                            let mut s = session();
                            let Some(alice) = s.alice.as_mut() else {
                                status.set(StatusMsg::err("Init first."));
                                return;
                            };
                            match double_ratchet_encrypt_internal(alice, plaintext.as_bytes()) {
                                Ok(msg) => {
                                    teach.write().push(format!(
                                        "Alice encrypt n={} ct={}",
                                        msg.message_number,
                                        hex_preview(&msg.ciphertext, 20)
                                    ));
                                    s.last_ciphertext = Some(msg);
                                    s.last_plaintext = None;
                                    session.set(s);
                                    status.set(StatusMsg::ok("Alice produced ciphertext."));
                                }
                                Err(e) => {
                                    status.set(StatusMsg::err(e.to_string()));
                                    return;
                                }
                            }
                        }
                        2 => {
                            let mut s = session();
                            let (Some(bob), Some(msg)) =
                                (s.bob.as_mut(), s.last_ciphertext.clone())
                            else {
                                status.set(StatusMsg::err("Need Alice ciphertext."));
                                return;
                            };
                            match double_ratchet_decrypt_internal(bob, &msg) {
                                Ok(pt) => {
                                    let text = String::from_utf8_lossy(&pt).to_string();
                                    teach.write().push(
                                        "Bob: DH ratchet + decrypt message 0".into(),
                                    );
                                    s.last_plaintext = Some(text.clone());
                                    session.set(s);
                                    status.set(StatusMsg::ok(format!("Bob decrypted: {text}")));
                                }
                                Err(e) => {
                                    status.set(StatusMsg::err(e.to_string()));
                                    return;
                                }
                            }
                        }
                        3 => {
                            let mut s = session();
                            let Some(bob) = s.bob.as_mut() else {
                                status.set(StatusMsg::err("Init first."));
                                return;
                            };
                            match double_ratchet_encrypt_internal(bob, b"reply from Bob") {
                                Ok(msg) => {
                                    teach.write().push(format!(
                                        "Bob encrypt reply n={}",
                                        msg.message_number
                                    ));
                                    s.last_ciphertext = Some(msg);
                                    s.last_plaintext = None;
                                    session.set(s);
                                    status.set(StatusMsg::ok("Bob encrypted a reply."));
                                }
                                Err(e) => {
                                    status.set(StatusMsg::err(e.to_string()));
                                    return;
                                }
                            }
                        }
                        4 => {
                            let mut s = session();
                            let (Some(alice), Some(msg)) =
                                (s.alice.as_mut(), s.last_ciphertext.clone())
                            else {
                                status.set(StatusMsg::err("Need Bob ciphertext."));
                                return;
                            };
                            match double_ratchet_decrypt_internal(alice, &msg) {
                                Ok(pt) => {
                                    let text = String::from_utf8_lossy(&pt).to_string();
                                    teach.write().push(
                                        "Alice: DH ratchet + decrypt Bob’s reply".into(),
                                    );
                                    s.last_plaintext = Some(text.clone());
                                    session.set(s);
                                    status.set(StatusMsg::ok(format!("Alice decrypted: {text}")));
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
                    session.set(Session::default());
                    teach.set(Vec::new());
                    status.set(StatusMsg::info(
                        "Press Next to initialize Alice and Bob’s ratchet states.",
                    ));
                },
            }
            div { class: "grid gap-3 md:grid-cols-2",
                CounterCard {
                    name: "Alice".to_string(),
                    send_n: a_send,
                    recv_n: a_recv,
                    skipped: a_skip,
                    has_send_chain: a_sc,
                    has_recv_chain: a_rc,
                }
                CounterCard {
                    name: "Bob".to_string(),
                    send_n: b_send,
                    recv_n: b_recv,
                    skipped: b_skip,
                    has_send_chain: b_sc,
                    has_recv_chain: b_rc,
                }
            }
            if let Some(pt) = session().last_plaintext {
                BodyText { "Last plaintext: {pt}" }
            }
            TeachBack { entries: teach() }
        }
    }
}
