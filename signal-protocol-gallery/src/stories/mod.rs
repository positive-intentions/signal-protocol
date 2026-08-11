//! Force-linked Signal Protocol gallery stories.

mod double_ratchet;
mod errors;
mod full_session;
mod keys;
mod skipped;
mod x3dh;

use whatsup_ui::gallery::{GuiStory, TuiStory};

pub static GUI_STORIES: &[&GuiStory] = &[
    &keys::GUI_STORY,
    &x3dh::GUI_STORY,
    &double_ratchet::GUI_STORY,
    &skipped::GUI_STORY,
    &full_session::GUI_STORY,
    &errors::GUI_STORY,
];

pub static TUI_STORIES: &[&TuiStory] = &[];
