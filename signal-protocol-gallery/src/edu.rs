//! Shared educational UI for paced Signal Protocol demos.

use dioxus::prelude::*;
use whatsup_ui::components::atoms::{BodyText, Button, ButtonVariant, Heading};

use crate::util::hex_preview;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum StatusKind {
    Info,
    Ok,
    Err,
}

#[derive(Clone, PartialEq)]
pub struct StatusMsg {
    pub kind: StatusKind,
    pub text: String,
}

impl StatusMsg {
    pub fn info(text: impl Into<String>) -> Self {
        Self {
            kind: StatusKind::Info,
            text: text.into(),
        }
    }
    pub fn ok(text: impl Into<String>) -> Self {
        Self {
            kind: StatusKind::Ok,
            text: text.into(),
        }
    }
    pub fn err(text: impl Into<String>) -> Self {
        Self {
            kind: StatusKind::Err,
            text: text.into(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct StepDef {
    pub title: &'static str,
    pub why: &'static str,
}

#[component]
pub fn DemoShell(title: String, children: Element) -> Element {
    rsx! {
        div { class: "flex h-full flex-col gap-4 overflow-auto p-4",
            Heading { "{title}" }
            {children}
        }
    }
}

#[component]
pub fn StepList(steps: Vec<StepDef>, current: usize) -> Element {
    rsx! {
        ol { class: "flex flex-wrap gap-2",
            for (i, step) in steps.iter().enumerate() {
                {
                    let active = i == current;
                    let done = i < current;
                    let cls = if active {
                        "border-wa-teal bg-wa-teal/15 text-wa-teal"
                    } else if done {
                        "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400"
                    } else {
                        "border-wa-border text-wa-muted dark:border-wa-border-dark"
                    };
                    let n = i + 1;
                    let title = step.title;
                    rsx! {
                        li { class: "rounded-full border px-3 py-1 text-xs font-semibold {cls}",
                            "{n}. {title}"
                        }
                    }
                }
            }
        }
    }
}

#[component]
pub fn StepHeader(steps: Vec<StepDef>, current: usize) -> Element {
    let step = steps.get(current);
    let n = current + 1;
    let total = steps.len();
    let title = step.map(|s| s.title).unwrap_or("Done");
    let why = step.map(|s| s.why).unwrap_or("Walk through is complete. Reset to try again.");

    rsx! {
        div { class: "space-y-2",
            StepList { steps: steps.clone(), current }
            div { class: "rounded-lg border border-wa-border bg-wa-panel/60 p-3 dark:border-wa-border-dark dark:bg-wa-panel-dark/60",
                p { class: "text-sm font-semibold text-wa-ink dark:text-wa-ink-dark",
                    "Step {n} of {total}: {title}"
                }
                BodyText { "{why}" }
            }
        }
    }
}

#[component]
pub fn StepControls(
    can_back: bool,
    can_next: bool,
    next_label: String,
    on_back: EventHandler<()>,
    on_next: EventHandler<()>,
    on_reset: EventHandler<()>,
) -> Element {
    rsx! {
        div { class: "flex flex-wrap gap-2",
            Button {
                variant: ButtonVariant::Secondary,
                onclick: move |_| {
                    if can_back {
                        on_back.call(());
                    }
                },
                "Back"
            }
            Button {
                variant: ButtonVariant::Primary,
                onclick: move |_| {
                    if can_next {
                        on_next.call(());
                    }
                },
                "{next_label}"
            }
            Button {
                variant: ButtonVariant::Secondary,
                onclick: move |_| on_reset.call(()),
                "Reset"
            }
        }
    }
}

#[component]
pub fn StatusBanner(status: StatusMsg) -> Element {
    let cls = match status.kind {
        StatusKind::Info => {
            "border-sky-500/40 bg-sky-500/10 text-sky-800 dark:text-sky-300"
        }
        StatusKind::Ok => {
            "border-emerald-500/40 bg-emerald-500/10 text-emerald-800 dark:text-emerald-300"
        }
        StatusKind::Err => "border-rose-500/40 bg-rose-500/10 text-rose-800 dark:text-rose-300",
    };
    rsx! {
        div { class: "rounded-lg border px-3 py-2 text-sm {cls}", "{status.text}" }
    }
}

#[component]
pub fn HexField(label: String, bytes: Option<Vec<u8>>, show_private: bool, is_private: bool) -> Element {
    let value = match (&bytes, is_private, show_private) {
        (None, _, _) => "—".to_string(),
        (Some(_), true, false) => "•••• (hidden — toggle Show private keys)".to_string(),
        (Some(b), _, _) => hex_preview(b, 40),
    };
    rsx! {
        div { class: "space-y-0.5",
            p { class: "text-[11px] font-semibold uppercase tracking-wide text-wa-muted dark:text-wa-muted-dark",
                "{label}"
            }
            code { class: "block break-all rounded bg-black/5 px-2 py-1 font-mono text-[11px] text-wa-ink dark:bg-white/5 dark:text-wa-ink-dark",
                "{value}"
            }
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct LabeledBytes {
    pub label: String,
    pub bytes: Option<Vec<u8>>,
    pub is_private: bool,
}

#[component]
pub fn PartyPanel(
    name: String,
    role: String,
    accent: String,
    fields: Vec<LabeledBytes>,
    show_private: bool,
) -> Element {
    let initial = name.chars().next().unwrap_or('?');
    rsx! {
        div { class: "flex min-w-0 flex-1 flex-col gap-3 rounded-xl border border-wa-border p-3 dark:border-wa-border-dark",
            div { class: "flex items-center gap-2",
                span { class: "inline-flex h-8 w-8 items-center justify-center rounded-full text-xs font-bold text-white {accent}",
                    "{initial}"
                }
                div {
                    p { class: "font-semibold text-wa-ink dark:text-wa-ink-dark", "{name}" }
                    p { class: "text-xs text-wa-muted dark:text-wa-muted-dark", "{role}" }
                }
            }
            div { class: "space-y-2",
                for field in fields {
                    HexField {
                        label: field.label,
                        bytes: field.bytes,
                        show_private,
                        is_private: field.is_private,
                    }
                }
            }
        }
    }
}

#[component]
pub fn TeachBack(entries: Vec<String>) -> Element {
    rsx! {
        div { class: "rounded-lg border border-wa-border p-3 dark:border-wa-border-dark",
            p { class: "mb-2 text-sm font-semibold text-wa-ink dark:text-wa-ink-dark",
                "Cryptographic operations"
            }
            if entries.is_empty() {
                BodyText { "Advance steps to see the operations performed." }
            } else {
                ul { class: "space-y-1.5 font-mono text-[11px] leading-relaxed text-wa-ink dark:text-wa-ink-dark",
                    for (i, line) in entries.iter().enumerate() {
                        {
                            let n = i + 1;
                            let line = line.clone();
                            rsx! {
                                li { class: "rounded bg-black/5 px-2 py-1 dark:bg-white/5",
                                    span { class: "mr-2 text-wa-muted", "{n}." }
                                    "{line}"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
pub fn MatchChip(label: String, matched: Option<bool>) -> Element {
    let (cls, text) = match matched {
        None => (
            "border-wa-border text-wa-muted dark:border-wa-border-dark",
            format!("{label}: —"),
        ),
        Some(true) => (
            "border-emerald-500/50 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300",
            format!("{label}: YES"),
        ),
        Some(false) => (
            "border-rose-500/50 bg-rose-500/15 text-rose-700 dark:text-rose-300",
            format!("{label}: NO"),
        ),
    };
    rsx! {
        span { class: "inline-flex rounded-full border px-3 py-1 text-xs font-bold {cls}", "{text}" }
    }
}

#[component]
pub fn PrivateToggle(show: bool, on_toggle: EventHandler<bool>) -> Element {
    let label = if show {
        "Hide private keys"
    } else {
        "Show private keys"
    };
    rsx! {
        Button {
            variant: ButtonVariant::Secondary,
            onclick: move |_| on_toggle.call(!show),
            "{label}"
        }
    }
}

#[component]
pub fn CounterCard(name: String, send_n: String, recv_n: String, skipped: String, has_send_chain: String, has_recv_chain: String) -> Element {
    rsx! {
        div { class: "rounded-lg border border-wa-border p-3 dark:border-wa-border-dark",
            p { class: "mb-1 font-semibold", "{name}" }
            BodyText { "send_n={send_n}  recv_n={recv_n}  skipped={skipped}" }
            BodyText { "sending_chain={has_send_chain}  receiving_chain={has_recv_chain}" }
        }
    }
}
