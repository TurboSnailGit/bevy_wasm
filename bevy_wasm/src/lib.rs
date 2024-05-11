//! Mod Bevy games with WebAssembly
//!
//! See [examples/cubes](https://github.com/BrandonDyer64/bevy_wasm/tree/main/examples/cubes)
//! for a comprehensive example of how to use this.
//!
//! For building mods, see the sister crate [bevy_wasm_sys](https://docs.rs/bevy_wasm_sys).

#![deny(missing_docs)]

use bevy::ecs::event::Event;
use bevy::prelude::Resource;
use bevy::reflect::TypePath;
use serde::de::DeserializeOwned;
use serde::Serialize;

pub mod components;
mod mod_state;
pub mod plugin;
mod runtime;
mod systems;
mod wasm_asset;

/// Any data type that can be used as a Host <-> Mod message
///
/// Must be [`Clone`], [`Send`], and [`Sync`], and must be (de)serializable with serde.
///
/// `bevy_wasm` uses `bincode` for serialization, so it's relatively fast.
pub trait Message: Send + Sync + Serialize + DeserializeOwned + Event + Clone + 'static {}

impl<T> Message for T where T: Send + Sync + Serialize + DeserializeOwned + Event + Clone + 'static {}

/// Any data type that can be used as a shared resource from Host to Mod
///
/// Must be [`Clone`], [`Send`], [`Sync`], and [`TypePath`], and must be (de)serializable with serde.
pub trait SharedResource: Resource + Serialize + DeserializeOwned + TypePath {}

impl<T> SharedResource for T where T: Resource + Serialize + DeserializeOwned + TypePath {}

/// Convinience exports
pub mod prelude {
    pub use bevy_wasm_shared::prelude::*;

    pub use crate::components::*;
    pub use crate::plugin::WasmPlugin;
    pub use crate::Message;
}
