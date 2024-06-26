use std::ops::Deref;
use std::sync::Arc;

use bevy::prelude::*;

use crate::runtime::WasmInstance;
use crate::SharedResource;

pub fn update_shared_resource<T: SharedResource>(
    res: Res<T>,
    mut wasm_mods: Query<&mut WasmInstance>,
) {
    if res.is_changed() {
        let v: &T = res.deref();
        let resource_bytes: Arc<[u8]> = match bincode::serialize(v) {
            Ok(bytes) => bytes.into(),
            Err(err) => {
                error!("Error while serializing resource: {}", err);
                return;
            }
        };

        for mut wasm_mod in wasm_mods.iter_mut() {
            wasm_mod.update_resource_value::<T>(resource_bytes.clone());
        }
    }
}
