use std::sync::{Arc, RwLock};

use bevy::prelude::{error, info, warn};
use bevy_wasm_shared::version::Version;
use colored::*;
use js_sys::{Object, Reflect, Uint8Array, WebAssembly};
use wasm_bindgen::closure::{IntoWasmClosure, WasmClosure};
use wasm_bindgen::prelude::*;

use crate::mod_state::ModState;

fn link<T>(target: &JsValue, name: &str, closure: impl IntoWasmClosure<T> + 'static)
where
    T: WasmClosure + ?Sized,
{
    let closure = Closure::new(closure);
    Reflect::set(target, &JsValue::from_str(name), closure.as_ref()).unwrap();
    Box::leak(Box::new(closure)); // TODO: Don't just leak the closures.
}

#[link(wasm_import_module = "__wbindgen_placeholder__")]
extern "C" {
    // wbindgen
    fn __wbindgen_describe(v: u32);
    fn __wbindgen_is_function(idx: u32) -> u32;
    fn __wbindgen_is_object(idx: u32) -> u32;
    fn __wbindgen_is_string(idx: u32) -> u32;
    fn __wbindgen_is_undefined(idx: u32) -> u32;
    fn __wbindgen_memory() -> u32;
    fn __wbindgen_object_clone_ref(idx: i32) -> i32;
    fn __wbindgen_object_drop_ref(idx: u32) -> ();
    fn __wbindgen_string_new(ptr: u32, len: u32) -> u32;

    // getrandom
    // Todo: Transform this into a macro
    fn __wbg_buffer_b914fb8b50ebbc3e(v: i32) -> i32;
    fn __wbg_call_3f093dd26d5569f8(x: i32, y: i32) -> i32;
    fn __wbg_call_67f2111acd2dfdb6(x: i32, y: i32, z: i32) -> i32;
    fn __wbg_crypto_d05b68a3572bb8ca(v: i32) -> i32;
    fn __wbg_getRandomValues_7e42b4fb8779dc6d(x: i32, y: i32);
    fn __wbg_global_f56b013ed9bcf359() -> i32;
    fn __wbg_globalThis_622105db80c1457d() -> i32;
    fn __wbg_msCrypto_10fc94afee92bd76(v: i32) -> i32;
    fn __wbg_new_b1f2d6842d615181(v: i32) -> i32;
    fn __wbg_newnoargs_cfecb3965268594c(x: i32, y: i32) -> i32;
    fn __wbg_newwithbyteoffsetandlength_0de9ee56e9f6ee6e(x: i32, y: i32, z: i32) -> i32;
    fn __wbg_newwithlength_0d03cef43b68a530(v: i32) -> i32;
    fn __wbg_node_43b1089f407e4ec2(v: i32) -> i32;
    fn __wbg_process_b02b3570280d0366(v: i32) -> i32;
    fn __wbg_randomFillSync_b70ccbdf4926a99d(x: i32, y: i32);
    fn __wbg_require_9a7e0f667ead4995() -> i32;
    fn __wbg_self_05040bd9523805b9() -> i32;
    fn __wbg_set_7d988c98e6ced92d(x: i32, y: i32, z: i32) -> i32;
    fn __wbg_subarray_adc418253d76e2f1(x: i32, y: i32, z: i32) -> i32;
    fn __wbg_versions_c1cb42213cedf0f5(v: i32) -> i32;
    fn __wbg_window_adc720039f2cb14f() -> i32;
}

#[allow(clippy::redundant_clone)]
pub fn build_linker(
    protocol_version: Version,
    mod_state: Arc<RwLock<ModState>>,
    memory: Arc<RwLock<Option<WebAssembly::Memory>>>,
) -> Object {
    let host = Object::new();

    link::<dyn FnMut(i32, u32)>(&host, "console_info", {
        let memory = memory.clone();
        move |ptr, len| {
            if let Some(memory) = memory.read().unwrap().as_ref() {
                let buffer = Uint8Array::new(&memory.buffer())
                    .slice(ptr as u32, ptr as u32 + len)
                    .to_vec();
                let text = std::str::from_utf8(&buffer).unwrap();
                info!("MOD: {}", text);
            }
        }
    });

    link::<dyn FnMut(i32, u32)>(&host, "console_warn", {
        let memory = memory.clone();
        move |ptr, len| {
            if let Some(memory) = memory.read().unwrap().as_ref() {
                let buffer = Uint8Array::new(&memory.buffer())
                    .slice(ptr as u32, ptr as u32 + len)
                    .to_vec();
                let text = std::str::from_utf8(&buffer).unwrap();
                warn!("MOD: {}", text);
            }
        }
    });

    link::<dyn FnMut(i32, u32)>(&host, "console_error", {
        let memory = memory.clone();
        move |ptr, len| {
            if let Some(memory) = memory.read().unwrap().as_ref() {
                let buffer = Uint8Array::new(&memory.buffer())
                    .slice(ptr as u32, ptr as u32 + len)
                    .to_vec();
                let text = std::str::from_utf8(&buffer).unwrap();
                error!("MOD: {}", text);
            }
        }
    });

    link::<dyn FnMut(i32)>(&host, "store_app", {
        let mod_state = mod_state.clone();
        move |ptr| {
            mod_state.write().unwrap().app_ptr = ptr;
            info!("{} 0x{:X}", "Storing app pointer:".italic(), ptr);
        }
    });

    link::<dyn FnMut() -> u64>(&host, "get_time_since_startup", {
        let mod_state = mod_state.clone();
        move || -> u64 { mod_state.read().unwrap().startup_time.elapsed().as_nanos() as u64 }
    });

    link::<dyn FnMut(i32, u32) -> u32>(&host, "get_next_event", {
        let mod_state = mod_state.clone();
        let memory = memory.clone();
        move |ptr: i32, len: u32| -> u32 {
            let next_event = mod_state.write().unwrap().events_in.pop_front();
            if let Some(next_event) = next_event {
                if next_event.len() > len as usize {
                    error!("Serialized event is too long");
                    return 0;
                }
                let arr = Uint8Array::from(&next_event[..]);
                if let Some(memory) = memory.read().unwrap().as_ref() {
                    Uint8Array::new(&memory.buffer()).set(&arr, ptr as u32);
                    next_event.len() as u32
                } else {
                    0
                }
            } else {
                0
            }
        }
    });

    link::<dyn FnMut(i32, u32)>(&host, "send_serialized_event", {
        let mod_state = mod_state.clone();
        let memory = memory.clone();
        move |ptr, len| {
            if let Some(memory) = memory.read().unwrap().as_ref() {
                let buffer = Uint8Array::new(&memory.buffer())
                    .slice(ptr as u32, ptr as u32 + len)
                    .to_vec();
                mod_state.write().unwrap().events_out.push(buffer.into());
            }
        }
    });

    link::<dyn FnMut() -> u64>(&host, "get_protocol_version", {
        move || -> u64 { protocol_version.to_u64() }
    });

    link::<dyn FnMut(i32, u32, i32, u32) -> u32>(&host, "get_resource", {
        let mod_state = mod_state.clone();
        let memory = memory.clone();
        move |type_path_buffer, type_path_buffer_len, buffer_ptr, buffer_len| -> u32 {
            let memory_read = memory.read().unwrap();
            let Some(memory) = memory_read.as_ref() else {
                return 0;
            };
            let utf8_buffer = Uint8Array::new(&memory.buffer())
                .slice(
                    type_path_buffer as u32,
                    type_path_buffer as u32 + type_path_buffer_len,
                )
                .to_vec();
            let type_path = std::str::from_utf8(&utf8_buffer).unwrap();

            let resource_bytes = mod_state
                .write()
                .unwrap()
                .shared_resource_values
                .remove(type_path);

            let Some(resource_bytes) = resource_bytes else {
                return 0;
            };
            if resource_bytes.len() > buffer_len as usize {
                error!("Serialized event is too long");
                return 0;
            }
            let arr = Uint8Array::from(&resource_bytes[..]);
            Uint8Array::new(&memory.buffer()).set(&arr, buffer_ptr as u32);
            resource_bytes.len() as u32
        }
    });

    // __wbindgen_placeholder__
    let wbp = Object::new();

    // Ref: https://rustwasm.github.io/wasm-bindgen/api/src/wasm_bindgen/lib.rs.html#1018
    link::<dyn FnMut(u32)>(&wbp, "__wbindgen_describe", {
        move |v| {
            info!("__wbindgen_describe: {}", v);
            //unsafe { __wbindgen_describe(v) }
        }
    });

    link::<dyn FnMut(i32, i32)>(&wbp, "__wbindgen_throw", {
        move |msg, len| {
            info!("__wbindgen_throw: {} {}", msg, len);
        }
    });

    link::<dyn FnMut() -> u32>(&wbp, "__wbindgen_memory", {
        move || {
            let memory = unsafe { __wbindgen_memory() };
            info!("__wbindgen_memory {memory}");
            memory
        }
    });

    link::<dyn FnMut(u32)>(&wbp, "__wbindgen_object_drop_ref", {
        move |v| {
            info!("__wbindgen_object_drop_ref: {v}");
            unsafe { __wbindgen_object_drop_ref(v) };
        }
    });

    link::<dyn FnMut(i32) -> i32>(&wbp, "__wbindgen_object_clone_ref", {
        move |idx| {
            let ret = unsafe { __wbindgen_object_clone_ref(idx) };
            info!("__wbindgen_object_clone_ref: {idx}, ret {idx}");
            ret
        }
    });

    link::<dyn FnMut(u32) -> u32>(&wbp, "__wbindgen_is_object", {
        move |v| {
            info!("__wbindgen_is_object: {v}");
            unsafe { __wbindgen_is_object(v) }
        }
    });
    link::<dyn FnMut(u32) -> u32>(&wbp, "__wbindgen_is_string", {
        move |v| {
            info!("__wbindgen_is_string: {v}");
            unsafe { __wbindgen_is_string(v) }
        }
    });

    link::<dyn FnMut(u32) -> u32>(&wbp, "__wbindgen_is_function", {
        move |v| {
            let ret = unsafe { __wbindgen_is_function(v) };
            info!("__wbindgen_is_function: {v}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(u32, u32) -> u32>(&wbp, "__wbindgen_string_new", {
        move |ptr, len| {
            info!("__wbindgen_string_new: len {len}");
            unsafe { __wbindgen_string_new(ptr, len) }
        }
    });

    link::<dyn FnMut(u32) -> u32>(&wbp, "__wbindgen_is_undefined", {
        move |v| {
            let is_undefined = unsafe { __wbindgen_is_undefined(v) };
            info!("__wbindgen_is_undefined: {v}, ret {is_undefined}");
            is_undefined
        }
    });

    // getrandom stuff
    // https://github.com/rust-random/getrandom/blob/5f0701faba5b83ebf144af9973582904f60849b7/src/js.rs#L115
    link::<dyn FnMut(i32) -> i32>(&wbp, "__wbg_buffer_b914fb8b50ebbc3e", {
        move |v| {
            let ret = unsafe { __wbg_buffer_b914fb8b50ebbc3e(v) };
            info!("__wbg_buffer_b914fb8b50ebbc3e: {v}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32, i32, i32) -> i32>(
        &wbp,
        "__wbg_newwithbyteoffsetandlength_0de9ee56e9f6ee6e",
        {
            move |x, y, z| {
                let ret = unsafe { __wbg_newwithbyteoffsetandlength_0de9ee56e9f6ee6e(x, y, z) };
                info!(
                    "__wbg_newwithbyteoffsetandlength_0de9ee56e9f6ee6e: {x}, {y}, {z}, ret {ret}"
                );
                ret
            }
        },
    );

    link::<dyn FnMut(i32, i32)>(&wbp, "__wbg_randomFillSync_b70ccbdf4926a99d", {
        move |x, y| {
            info!("__wbg_randomFillSync_b70ccbdf4926a99d: {x}, {y}");
            unsafe { __wbg_randomFillSync_b70ccbdf4926a99d(x, y) };
        }
    });

    link::<dyn FnMut(i32, i32, i32) -> i32>(&wbp, "__wbg_subarray_adc418253d76e2f1", {
        move |x, y, z| {
            let ret = unsafe { __wbg_subarray_adc418253d76e2f1(x, y, z) };
            info!("__wbg_subarray_adc418253d76e2f1: {x}, {y}, {z}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32, i32)>(&wbp, "__wbg_getRandomValues_7e42b4fb8779dc6d", {
        move |x, y| {
            info!("__wbg_getRandomValues_7e42b4fb8779dc6d: {x}, {y}");
            unsafe { __wbg_getRandomValues_7e42b4fb8779dc6d(x, y) };
        }
    });

    link::<dyn FnMut(i32) -> i32>(&wbp, "__wbg_new_b1f2d6842d615181", {
        move |v| {
            let ret = unsafe { __wbg_new_b1f2d6842d615181(v) };
            info!("__wbg_new_b1f2d6842d615181: {v}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32, i32, i32)>(&wbp, "__wbg_set_7d988c98e6ced92d", {
        move |x, y, z| {
            info!("__wbg_set_7d988c98e6ced92d: {x}, {y}, {z}");
            unsafe { __wbg_set_7d988c98e6ced92d(x, y, z) };
        }
    });

    link::<dyn FnMut(i32) -> i32>(&wbp, "__wbg_crypto_d05b68a3572bb8ca", {
        move |v| {
            let ret = unsafe { __wbg_crypto_d05b68a3572bb8ca(v) };
            info!("__wbg_crypto_d05b68a3572bb8ca: {v}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32) -> i32>(&wbp, "__wbg_process_b02b3570280d0366", {
        move |v| {
            let ret = unsafe { __wbg_process_b02b3570280d0366(v) };
            info!("__wbg_process_b02b3570280d0366: {v}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32) -> i32>(&wbp, "__wbg_versions_c1cb42213cedf0f5", {
        move |v| {
            let ret = unsafe { __wbg_versions_c1cb42213cedf0f5(v) };
            info!("__wbg_versions_c1cb42213cedf0f5: {v}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32) -> i32>(&wbp, "__wbg_node_43b1089f407e4ec2", {
        move |v| {
            let ret = unsafe { __wbg_node_43b1089f407e4ec2(v) };
            info!("__wbg_node_43b1089f407e4ec2: {v}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut() -> i32>(&wbp, "__wbg_require_9a7e0f667ead4995", {
        move || {
            let ret = unsafe { __wbg_require_9a7e0f667ead4995() };
            info!("__wbg_require_9a7e0f667ead4995: ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32, i32, i32) -> i32>(&wbp, "__wbg_call_67f2111acd2dfdb6", {
        move |x, y, z| {
            let ret = unsafe { __wbg_call_67f2111acd2dfdb6(x, y, z) };
            info!("__wbg_call_67f2111acd2dfdb6: {x}, {y}, {z}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32) -> i32>(&wbp, "__wbg_msCrypto_10fc94afee92bd76", {
        move |v| {
            let ret = unsafe { __wbg_msCrypto_10fc94afee92bd76(v) };
            info!("__wbg_msCrypto_10fc94afee92bd76: {v}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32) -> i32>(&wbp, "__wbg_newwithlength_0d03cef43b68a530", {
        move |v| {
            let ret = unsafe { __wbg_newwithlength_0d03cef43b68a530(v) };
            info!("__wbg_newwithlength_0d03cef43b68a530: {v}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut() -> i32>(&wbp, "__wbg_self_05040bd9523805b9", {
        move || {
            let ret = unsafe { __wbg_self_05040bd9523805b9() };
            info!("__wbg_self_05040bd9523805b9: ret {ret}");
            ret
        }
    });

    link::<dyn FnMut() -> i32>(&wbp, "__wbg_window_adc720039f2cb14f", {
        move || {
            let ret = unsafe { __wbg_window_adc720039f2cb14f() };
            info!("__wbg_window_adc720039f2cb14f: ret {ret}");
            ret
        }
    });

    link::<dyn FnMut() -> i32>(&wbp, "__wbg_globalThis_622105db80c1457d", {
        move || {
            let ret = unsafe { __wbg_globalThis_622105db80c1457d() };
            info!("__wbg_globalThis_622105db80c1457d: ret {ret}");
            ret
        }
    });

    link::<dyn FnMut() -> i32>(&wbp, "__wbg_global_f56b013ed9bcf359", {
        move || {
            let ret = unsafe { __wbg_global_f56b013ed9bcf359() };
            info!("__wbg_global_f56b013ed9bcf359: ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32, i32) -> i32>(&wbp, "__wbg_newnoargs_cfecb3965268594c", {
        move |x, y| {
            let ret = unsafe { __wbg_newnoargs_cfecb3965268594c(x, y) };
            info!("__wbg_newnoargs_cfecb3965268594c: {x}, {y}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32, i32) -> i32>(&wbp, "__wbg_call_3f093dd26d5569f8", {
        move |x, y| {
            let ret = unsafe { __wbg_call_3f093dd26d5569f8(x, y) };
            info!("__wbg_call_3f093dd26d5569f8: {x}, {y}, ret {ret}");
            ret
        }
    });

    // __wbindgen_externref_xform__
    let wbxf = Object::new();

    link::<dyn FnMut(i32) -> i32>(&wbxf, "__wbindgen_externref_table_grow", {
        move |v| -> i32 {
            info!("__wbindgen_externref_table_grow: {}", v);
            0
        }
    });

    link::<dyn FnMut(i32)>(&wbxf, "__wbindgen_externref_table_set_null", {
        move |v| {
            info!("__wbindgen_externref_table_set_null: {}", v);
        }
    });

    let imports = Object::new();
    Reflect::set(
        &imports,
        &JsValue::from_str("__wbindgen_placeholder__"),
        &wbp,
    )
    .unwrap();
    Reflect::set(
        &imports,
        &JsValue::from_str("__wbindgen_externref_xform__"),
        &wbxf,
    )
    .unwrap();
    Reflect::set(&imports, &JsValue::from_str("host"), &host).unwrap();
    imports
}
