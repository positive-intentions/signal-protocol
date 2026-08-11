//! Shared formatting helpers for demo UIs.

pub fn hex_preview(bytes: &[u8], max: usize) -> String {
    let full = hex::encode(bytes);
    if full.len() <= max {
        full
    } else {
        format!("{}…", &full[..max])
    }
}
