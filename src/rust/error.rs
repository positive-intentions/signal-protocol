//! Error handling for Signal Protocol implementation
//!
//! Re-exports SignalError from signal-protocol-core and adds WASM compatibility.

pub use signal_protocol_core::SignalError;
use wasm_bindgen::prelude::*;

/// Convert SignalError to JavaScript-compatible JsValue (orphan rule prevents From impl).
/// Host unit tests cannot exercise `JsValue`; excluded from llvm-cov line gate.
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn signal_error_to_js_value(err: SignalError) -> JsValue {
    JsValue::from_str(&err.to_string())
}
