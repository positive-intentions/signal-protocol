use dioxus::prelude::*;
use signal_protocol_core::{
    double_ratchet_decrypt_internal, double_ratchet_encrypt_internal,
    initialize_double_ratchet_internal, DoubleRatchetMessage, DoubleRatchetState,
};
use whatsup_ui::components::atoms::BodyText;

use crate::edu::{
    CounterCard, DemoShell, StatusBanner, StatusMsg, StepControls, StepDef, StepHeader, TeachBack,
};

const STEPS: &[StepDef] = &[
    StepDef {
        title: "Init",
        why: "Create Alice (initiator) and Bob (responder) ratchet states from one shared root.",
    },
    StepDef {
        title: "Encrypt 0..2",
        why: "Alice encrypts three messages in order. On the wire they can arrive in any order.",
    },
    StepDef {
        title: "Deliver msg-2 first",
        why: "Bob decrypts the newest message first and stores skipped keys for msg-0 and msg-1.",
    },
    StepDef {
        title: "Deliver delayed msg-0",
        why: "The earlier ciphertext still decrypts using a skipped message key.",
    },
    StepDef {
        title: "Inspect",
        why: "Review the timeline and skipped-key count — this is how out-of-order delivery stays secure.",
    },
];

whatsup_ui::register_gui_story! {
    name: "Skipped / out-of-order",
    group: "Signal Protocol",
    docs: include_str!("skipped.md"),
    knobs: [],
    render: |_| {
        rsx! { SkippedDemo {} }
    },
}

#[derive(Clone, Default)]
struct SkipSession {
    alice: Option<DoubleRatchetState>,
    bob: Option<DoubleRatchetState>,
    msgs: Vec<DoubleRatchetMessage>,
    timeline: Vec<String>,
}

#[component]
fn SkippedDemo() -> Element {
    let mut step = use_signal(|| 0usize);
    let mut session = use_signal(SkipSession::default);
    let mut teach = use_signal(Vec::<String>::new);
    let mut status = use_signal(|| StatusMsg::info("Press Next to initialize the session."));

    let steps: Vec<StepDef> = STEPS.to_vec();
    let current = step();
    let at_end = current >= STEPS.len();
    let s = session();
    let skipped = s
        .bob
        .as_ref()
        .map(|b| b.skipped_message_keys.len().to_string())
        .unwrap_or_else(|| "—".into());
    let (b_send, b_recv) = match &s.bob {
        Some(b) => (
            b.sending_message_number.to_string(),
            b.receiving_message_number.to_string(),
        ),
        None => ("—".into(), "—".into()),
    };

    rsx! {
        DemoShell { title: "Skipped / out-of-order".to_string(),
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
                            root[0] = 0x11;
                            root[31] = 0x22;
                            match (
                                initialize_double_ratchet_internal(&root, true),
                                initialize_double_ratchet_internal(&root, false),
                            ) {
                                (Ok(alice), Ok(bob)) => {
                                    session.set(SkipSession {
                                        alice: Some(alice),
                                        bob: Some(bob),
                                        msgs: Vec::new(),
                                        timeline: vec!["Session ready (Alice initiator)".into()],
                                    });
                                    teach.write().push("DR init for Alice + Bob".into());
                                    status.set(StatusMsg::ok("Initialized."));
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
                            let mut msgs = Vec::new();
                            for i in 0..3 {
                                let body = format!("msg-{i}");
                                match double_ratchet_encrypt_internal(alice, body.as_bytes()) {
                                    Ok(m) => msgs.push(m),
                                    Err(e) => {
                                        status.set(StatusMsg::err(e.to_string()));
                                        return;
                                    }
                                }
                            }
                            s.msgs = msgs;
                            s.timeline.push("Alice encrypted msg-0, msg-1, msg-2 (in order)".into());
                            session.set(s);
                            teach.write().push("encrypt ×3 → ciphertext queue [0,1,2]".into());
                            status.set(StatusMsg::ok("Three ciphertexts queued."));
                        }
                        2 => {
                            let mut s = session();
                            let Some(msg2) = s.msgs.get(2).cloned() else {
                                status.set(StatusMsg::err("Encrypt first."));
                                return;
                            };
                            let Some(bob) = s.bob.as_mut() else {
                                status.set(StatusMsg::err("Init first."));
                                return;
                            };
                            match double_ratchet_decrypt_internal(bob, &msg2) {
                                Ok(pt) => {
                                    let text = String::from_utf8_lossy(&pt).to_string();
                                    let n = bob.skipped_message_keys.len();
                                    s.timeline.push(format!(
                                        "Delivered msg-2 first → decrypted \"{text}\" (skipped keys={n})"
                                    ));
                                    session.set(s);
                                    teach.write().push(format!(
                                        "Out-of-order decrypt stores {n} skipped message keys"
                                    ));
                                    status.set(StatusMsg::ok(format!(
                                        "msg-2 ok; skipped keys = {n}"
                                    )));
                                }
                                Err(e) => {
                                    status.set(StatusMsg::err(e.to_string()));
                                    return;
                                }
                            }
                        }
                        3 => {
                            let mut s = session();
                            let Some(msg0) = s.msgs.first().cloned() else {
                                status.set(StatusMsg::err("Encrypt first."));
                                return;
                            };
                            let Some(bob) = s.bob.as_mut() else {
                                status.set(StatusMsg::err("Init first."));
                                return;
                            };
                            match double_ratchet_decrypt_internal(bob, &msg0) {
                                Ok(pt) => {
                                    let text = String::from_utf8_lossy(&pt).to_string();
                                    s.timeline.push(format!(
                                        "Delivered delayed msg-0 → decrypted \"{text}\" via skipped key"
                                    ));
                                    session.set(s);
                                    teach.write().push(
                                        "decrypt(msg-0) used a previously skipped message key".into(),
                                    );
                                    status.set(StatusMsg::ok("Delayed msg-0 decrypted."));
                                }
                                Err(e) => {
                                    status.set(StatusMsg::err(e.to_string()));
                                    return;
                                }
                            }
                        }
                        4 => {
                            let n = session()
                                .bob
                                .as_ref()
                                .map(|b| b.skipped_message_keys.len())
                                .unwrap_or(0);
                            teach.write().push(format!(
                                "Inspect: remaining skipped keys={n}; timeline shows delivery order"
                            ));
                            status.set(StatusMsg::ok(
                                "Tour complete — out-of-order delivery handled.",
                            ));
                        }
                        _ => {}
                    }
                    step.set(current + 1);
                },
                on_reset: move |_| {
                    step.set(0);
                    session.set(SkipSession::default());
                    teach.set(Vec::new());
                    status.set(StatusMsg::info("Press Next to initialize the session."));
                },
            }
            CounterCard {
                name: "Bob".to_string(),
                send_n: b_send,
                recv_n: b_recv,
                skipped: skipped.clone(),
                has_send_chain: "—".to_string(),
                has_recv_chain: "—".to_string(),
            }
            div { class: "rounded-lg border border-wa-border p-3 dark:border-wa-border-dark",
                p { class: "mb-2 text-sm font-semibold", "Delivery timeline" }
                if session().timeline.is_empty() {
                    BodyText { "No events yet." }
                } else {
                    ol { class: "list-decimal space-y-1 pl-5 text-sm text-wa-ink dark:text-wa-ink-dark",
                        for line in session().timeline {
                            li { "{line}" }
                        }
                    }
                }
            }
            TeachBack { entries: teach() }
        }
    }
}
