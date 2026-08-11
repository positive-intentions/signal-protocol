//! Local-only Signal Protocol gallery (Dioxus + whatsup-ui chrome).
//!
//! Run from this crate directory:
//! `dx serve --bin signal-protocol-gallery --platform desktop`
//! or `cargo run`.

mod app;
mod edu;
mod stories;
mod util;

fn main() {
    dioxus::launch(app::App);
}
