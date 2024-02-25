use std::time::Instant;

use anyhow::Result;
use bevy::prelude::*;
use bevy_wasm_shared::prelude::*;
use colored::*;
use wasmtime::*;

use crate::mod_state::ModState;

pub(crate) fn build_linker(engine: &Engine, protocol_version: Version) -> Result<Linker<ModState>> {
    let mut linker: Linker<ModState> = Linker::new(engine);

    linker.func_wrap(
        "host",
        "console_info",
        |mut caller: Caller<'_, ModState>, msg: i32, len: u32| {
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(mem)) => mem,
                _ => panic!("failed to find mod memory"),
            };

            let Some(data) = mem
                .data(&caller)
                .get(msg as u32 as usize..)
                .and_then(|arr| arr.get(..len as usize))
            else {
                error!("Failed to get data from memory");
                return;
            };

            // SAFETY: We know that the memory is valid UTF-8 because it was written from a string in the mod
            let string = unsafe { std::str::from_utf8_unchecked(data) };
            info!(target: "MOD", "{}", string);
        },
    )?;
    linker.func_wrap(
        "host",
        "console_warn",
        |mut caller: Caller<'_, ModState>, msg: i32, len: u32| {
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(mem)) => mem,
                _ => panic!("failed to find mod memory"),
            };

            let Some(data) = mem
                .data(&caller)
                .get(msg as u32 as usize..)
                .and_then(|arr| arr.get(..len as usize))
            else {
                error!("Failed to get data from memory");
                return;
            };

            // SAFETY: We know that the memory is valid UTF-8 because it was written from a string in the mod
            let string = unsafe { std::str::from_utf8_unchecked(data) };
            warn!(target: "MOD", "{}", string);
        },
    )?;
    linker.func_wrap(
        "host",
        "console_error",
        |mut caller: Caller<'_, ModState>, msg: i32, len: u32| {
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(mem)) => mem,
                _ => panic!("failed to find mod memory"),
            };

            let Some(data) = mem
                .data(&caller)
                .get(msg as u32 as usize..)
                .and_then(|arr| arr.get(..len as usize))
            else {
                error!("Failed to get data from memory");
                return;
            };

            // SAFETY: We know that the memory is valid UTF-8 because it was written from a string in the mod
            let string = unsafe { std::str::from_utf8_unchecked(data) };
            error!(target: "MOD", "{}", string);
        },
    )?;
    linker.func_wrap(
        "host",
        "store_app",
        |mut caller: Caller<'_, ModState>, app_ptr: i32| {
            caller.data_mut().app_ptr = app_ptr;
            info!("{} 0x{:X}", "Storing app pointer:".italic(), app_ptr);
        },
    )?;
    linker.func_wrap(
        "host",
        "send_serialized_event",
        |mut caller: Caller<'_, ModState>, msg: i32, len: u32| {
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(mem)) => mem,
                _ => panic!("failed to find mod memory"),
            };

            let Some(data) = mem
                .data(&caller)
                .get(msg as u32 as usize..)
                .and_then(|arr| arr.get(..len as usize))
                .map(|x| x.into())
            else {
                error!("Failed to get data from memory");
                return;
            };

            caller.data_mut().events_out.push(data);
        },
    )?;
    linker.func_wrap(
        "host",
        "get_next_event",
        |mut caller: Caller<'_, ModState>, arena: i32, len: u32| -> u32 {
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(mem)) => mem,
                _ => panic!("failed to find mod memory"),
            };

            let Some(serialized_event) = caller.data_mut().events_in.pop_front() else {
                return 0;
            };

            let Some(buffer) = mem
                .data_mut(&mut caller)
                .get_mut(arena as u32 as usize..)
                .and_then(|arr| arr.get_mut(..len as usize))
            else {
                error!("Failed to get data from memory");
                return 0;
            };

            buffer[..serialized_event.len()].copy_from_slice(&serialized_event);
            serialized_event.len() as u32
        },
    )?;
    linker.func_wrap(
        "host",
        "get_resource",
        |mut caller: Caller<'_, ModState>,
         type_path_buffer: i32,
         type_path_buffer_len: u32,
         buffer: i32,
         buffer_len: u32|
         -> u32 {
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(mem)) => mem,
                _ => panic!("failed to find mod memory"),
            };

            let Some(type_path_data) = mem
                .data(&caller)
                .get(type_path_buffer as u32 as usize..)
                .and_then(|arr| arr.get(..type_path_buffer_len as usize))
            else {
                error!("Failed to get type_path_buffer from memory");
                return 0;
            };

            // Todo: Find a way to prevent this memory allocation.
            // SAFETY: We know that the memory is valid UTF-8 because it was written from a string in the mod
            let type_path = unsafe { std::str::from_utf8_unchecked(type_path_data).to_string() };

            let resource_bytes = caller
                .data_mut()
                .shared_resource_values
                .remove(type_path.as_str());

            let resource_bytes = match resource_bytes {
                Some(resource_bytes) => resource_bytes,
                None => return 0,
            };

            let Some(buffer) = mem
                .data_mut(&mut caller)
                .get_mut(buffer as u32 as usize..)
                .and_then(|arr| arr.get_mut(..buffer_len as usize))
            else {
                error!("Failed to get data from memory");
                return 0;
            };

            buffer[..resource_bytes.len()].copy_from_slice(&resource_bytes);
            resource_bytes.len() as u32
        },
    )?;
    linker.func_wrap(
        "host",
        "get_time_since_startup",
        |caller: Caller<'_, ModState>| -> u64 {
            let startup_time = caller.data().startup_time;
            let delta = Instant::now() - startup_time;
            delta.as_nanos() as u64
        },
    )?;
    linker.func_wrap("host", "get_protocol_version", move || -> u64 {
        protocol_version.to_u64()
    })?;

    // Because bevy wants to use wasm-bindgen
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbindgen_describe",
        |v: i32| {
            info!("__wbindgen_describe: {v}");
        },
    )?;

    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbindgen_memory",
        || -> i32 {
            info!("__wbindgen_memory");
            0
        },
    )?;

    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbg_buffer_b914fb8b50ebbc3e",
        |v: i32| -> i32 {
            info!("__wbg_buffer_b914fb8b50ebbc3e: {v}");
            0
        },
    )?;

    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbg_newwithbyteoffsetandlength_0de9ee56e9f6ee6e",
        |v: i32| -> i32 {
            info!("__wbg_newwithbyteoffsetandlength_0de9ee56e9f6ee6e: {v}");
            0
        },
    )?;

    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbindgen_object_drop_ref",
        |v: i32| {
            info!("__wbindgen_object_drop_ref: {v}");
        },
    )?;

    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbg_randomFillSync_b70ccbdf4926a99d",
        |v: i32, w: i32| {
            info!("__wbg_randomFillSync_b70ccbdf4926a99d: {v}, {w}");
        },
    )?;

    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbg_subarray_adc418253d76e2f1",
        |x: i32, y: i32, z: i32| -> i32 {
            info!("__wbg_subarray_adc418253d76e2f1: {x}, {y}, {z}");
            0
        },
    )?;

    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbg_getRandomValues_7e42b4fb8779dc6d",
        |x: i32, y: i32| {
            info!("__wbg_getRandomValues_7e42b4fb8779dc6d: {x}, {y}");
        },
    )?;
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbg_new_b1f2d6842d615181",
        |v: i32| -> i32 {
            info!("__wbg_new_b1f2d6842d615181: {v}");
            0
        },
    )?;
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbg_set_7d988c98e6ced92d",
        |x: i32, y: i32, z: i32| {
            info!("__wbg_set_7d988c98e6ced92d: {x}, {y}, {z}");
        },
    )?;
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbindgen_describe",
        |v: i32| {
            info!("__wbindgen_describe: {v}");
        },
    )?;
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbindgen_object_clone_ref",
        |v: i32| -> i32 {
            info!("__wbindgen_object_clone_ref: {v}");
            0
        },
    )?;
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbg_crypto_d05b68a3572bb8ca",
        |v: i32| -> i32 {
            info!("__wbg_crypto_d05b68a3572bb8ca: {v}");
            0
        },
    )?;
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbindgen_is_object",
        |v: i32| -> i32 {
            info!("__wbindgen_is_object: {v}");
            0
        },
    )?;
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbg_process_b02b3570280d0366",
        |v: i32| -> i32 {
            info!("__wbg_process_b02b3570280d0366: {v}");
            0
        },
    )?;
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbg_versions_c1cb42213cedf0f5",
        |v: i32| -> i32 {
            info!("__wbg_versions_c1cb42213cedf0f5: {v}");
            0
        },
    )?;
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbg_node_43b1089f407e4ec2",
        |v: i32| -> i32 {
            info!("__wbg_node_43b1089f407e4ec2: {v}");
            0
        },
    )?;
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbindgen_is_string",
        |v: i32| -> i32 {
            info!("__wbindgen_is_string: {v}");
            0
        },
    )?;
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbg_require_9a7e0f667ead4995",
        || -> i32 {
            info!("__wbg_require_9a7e0f667ead4995");
            0
        },
    )?;
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbindgen_is_function",
        |v: i32| -> i32 {
            info!("__wbindgen_is_function: {v}");
            0
        },
    )?;
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbindgen_string_new",
        |x: i32, y: i32| -> i32 {
            info!("__wbindgen_string_new: {x}, {y}");
            0
        },
    )?;
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbg_call_67f2111acd2dfdb6",
        |x: i32, y: i32, z: i32| -> i32 {
            info!("__wbg_call_67f2111acd2dfdb6: {x}, {y}, {z}");
            0
        },
    )?;
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbg_msCrypto_10fc94afee92bd76",
        |v: i32| -> i32 {
            info!("__wbg_msCrypto_10fc94afee92bd76: {v}");
            0
        },
    )?;
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbg_newwithlength_0d03cef43b68a530",
        |v: i32| -> i32 {
            info!("__wbg_newwithlength_0d03cef43b68a530: {v}");
            0
        },
    )?;
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbg_self_05040bd9523805b9",
        || -> i32 {
            info!("__wbg_self_05040bd9523805b9");
            0
        },
    )?;
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbg_window_adc720039f2cb14f",
        || -> i32 {
            info!("__wbg_window_adc720039f2cb14f");
            0
        },
    )?;
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbg_globalThis_622105db80c1457d",
        || -> i32 {
            info!("__wbg_globalThis_622105db80c1457d");
            0
        },
    )?;
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbg_global_f56b013ed9bcf359",
        || -> i32 {
            info!("__wbg_global_f56b013ed9bcf359");
            0
        },
    )?;
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbindgen_is_undefined",
        |v: i32| -> i32 {
            info!("__wbindgen_is_undefined: {v}");
            0
        },
    )?;
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbg_newnoargs_cfecb3965268594c",
        |x: i32, y: i32| -> i32 {
            info!("__wbg_newnoargs_cfecb3965268594c: {x}, {y}");
            0
        },
    )?;
    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbg_call_3f093dd26d5569f8",
        |x: i32, y: i32| -> i32 {
            info!("__wbg_call_3f093dd26d5569f8: {x}, {y}");
            0
        },
    )?;

    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbindgen_throw",
        |mut caller: Caller<'_, ModState>, msg: i32, len: i32| {
            let mem = match caller.get_export("memory") {
                Some(Extern::Memory(mem)) => mem,
                _ => panic!("failed to find mod memory"),
            };

            let Some(data) = mem
                .data(&caller)
                .get(msg as u32 as usize..)
                .and_then(|arr| arr.get(..len as usize))
            else {
                error!("Failed to get data from memory");
                return;
            };

            // SAFETY: We know that the memory is valid UTF-8 because it was written from a string in the mod
            let string = unsafe { std::str::from_utf8_unchecked(data) };
            info!("{}", string);
        },
    )?;
    linker.func_wrap(
        "__wbindgen_externref_xform__",
        "__wbindgen_externref_table_grow",
        |v: i32| -> i32 {
            info!("__wbindgen_externref_table_grow: {v}");
            0
        },
    )?;
    linker.func_wrap(
        "__wbindgen_externref_xform__",
        "__wbindgen_externref_table_set_null",
        |v: i32| {
            info!("__wbindgen_externref_table_set_null: {v}");
        },
    )?;
    Ok(linker)
}
