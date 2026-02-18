//! Error handling for Signal Protocol implementation
//!
//! Re-exports SignalError from signal-protocol-core and adds WASM compatibility.

use wasm_bindgen::prelude::*;
pub use signal_protocol_core::SignalError;

/// Convert SignalError to JavaScript-compatible JsValue (orphan rule prevents From impl)
pub fn signal_error_to_js_value(err: SignalError) -> JsValue {
    JsValue::from_str(&err.to_string())
}