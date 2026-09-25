//! The graphical interface.

pub mod app;
pub mod entries;
pub mod icons;
pub mod settings;
pub mod setup;
#[cfg(all(test, feature = "ui-snapshots"))]
mod snapshots;
pub mod theme;
pub mod unlock;
pub mod widgets;

pub use app::App;
