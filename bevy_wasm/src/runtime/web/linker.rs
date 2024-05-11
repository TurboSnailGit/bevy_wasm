use std::sync::Arc;

use bevy::prelude::{error, info, warn};
use bevy_wasm_shared::version::Version;
use colored::*;
use js_sys::{Object, Reflect, Uint8Array, WebAssembly};
use parking_lot::RwLock;
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
    fn __wbindgen_cb_drop(v: i32) -> i32;
    fn __wbindgen_debug_string(x: i32, y: i32);
    fn __wbindgen_describe_closure(x: i32, y: i32, z: i32) -> i32;
    fn __wbindgen_is_function(idx: u32) -> u32;
    fn __wbindgen_is_object(idx: u32) -> u32;
    fn __wbindgen_is_string(idx: u32) -> u32;
    fn __wbindgen_is_undefined(idx: u32) -> u32;
    fn __wbindgen_memory() -> u32;
    fn __wbindgen_object_clone_ref(idx: i32) -> i32;
    fn __wbindgen_object_drop_ref(idx: u32);
    fn __wbindgen_string_new(ptr: u32, len: u32) -> u32;
    //fn __wbindgen_throw(x: i32, y: i32);
    //fn __wbindgen_describe(v: u32);

    // getrandom
    // Todo: Transform this into a macro
    fn __wbg_buffer_12d079cc21e14bdb(v: i32) -> i32;
    fn __wbg_call_27c0f87801dedf93(x: i32, y: i32) -> i32;
    fn __wbg_call_b3ca7c6051f9bec1(x: i32, y: i32, z: i32) -> i32;
    fn __wbg_crypto_566d7465cdbb6b7a(v: i32) -> i32;
    fn __wbg_error_f851667af71bcfc6(x: i32, y: i32);
    fn __wbg_getRandomValues_260cc23a41afad9a(x: i32, y: i32);
    fn __wbg_global_207b558942527489() -> i32;
    fn __wbg_globalThis_d1e6af4856ba331b() -> i32;
    fn __wbg_instanceof_Window_f401953a2cf86220(v: i32) -> i32;
    fn __wbg_log_aba5996d9bde071f(x: i32, y: i32);
    fn __wbg_log_c9486ca5d8e2cbe8(x: i32, y: i32);
    fn __wbg_mark_40e050a77cc39fea(x: i32, y: i32);
    fn __wbg_measure_aa7a73f17813f708(a: i32, b: i32, c: i32, d: i32);
    fn __wbg_msCrypto_0b84745e9245cdf6(v: i32) -> i32;
    fn __wbg_new_63b92bc8671ed464(v: i32) -> i32;
    fn __wbg_new_abda76e883ba8a5f() -> i32;
    fn __wbg_newnoargs_e258087cd0daa0ea(x: i32, y: i32) -> i32;
    fn __wbg_newwithbyteoffsetandlength_aa4a17c33a06e5cb(x: i32, y: i32, z: i32) -> i32;
    fn __wbg_newwithlength_e9b4878cebadb3d3(v: i32) -> i32;
    fn __wbg_node_caaf83d002149bd5(v: i32) -> i32;
    fn __wbg_now_e0d8ec93dd25766a(v: i32) -> f64;
    fn __wbg_performance_eeefc685c9bc38b4(v: i32) -> i32;
    fn __wbg_process_dc09a8c7d59982f6(v: i32) -> i32;
    fn __wbg_randomFillSync_290977693942bf03(x: i32, y: i32);
    fn __wbg_require_94a9da52636aacbf() -> i32;
    fn __wbg_self_ce0dbfc45cf2f5be() -> i32;
    fn __wbg_set_a47bac70306a19a7(x: i32, y: i32, z: i32) -> i32;
    fn __wbg_setTimeout_c172d5704ef82276(x: i32, y: i32, z: i32) -> i32;
    fn __wbg_stack_658279fe44541cf6(x: i32, y: i32);
    fn __wbg_subarray_a1f73cd4b5b42fe1(x: i32, y: i32, z: i32) -> i32;
    fn __wbg_versions_d98c6400c6ca2bd8(v: i32) -> i32;
    fn __wbg_window_c6fb939a7f436783() -> i32;
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
            if let Some(memory) = memory.read().as_ref() {
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
            if let Some(memory) = memory.read().as_ref() {
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
            if let Some(memory) = memory.read().as_ref() {
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
            mod_state.write().app_ptr = ptr;
            info!("{} 0x{:X}", "Storing app pointer:".italic(), ptr);
        }
    });

    link::<dyn FnMut() -> u64>(&host, "get_time_since_startup", {
        let mod_state = mod_state.clone();
        move || -> u64 { mod_state.read().startup_time.elapsed().as_nanos() as u64 }
    });

    link::<dyn FnMut() -> u64>(&host, "get_protocol_version", {
        move || -> u64 { protocol_version.to_u64() }
    });

    link::<dyn FnMut(i32, u32)>(&host, "send_serialized_event", {
        let mod_state = mod_state.clone();
        let memory = memory.clone();
        move |ptr, len| {
            if let Some(memory) = memory.read().as_ref() {
                let buffer = Uint8Array::new(&memory.buffer())
                    .slice(ptr as u32, ptr as u32 + len)
                    .to_vec();
                mod_state.write().events_out.push(buffer.into());
            }
        }
    });

    // TODO: FIX THOSE FUNCTIONS
    link::<dyn FnMut(i32, u32) -> u32>(&host, "get_next_event", {
        let mod_state = mod_state.clone();
        let memory = memory.clone();
        move |ptr: i32, len: u32| -> u32 {
            let next_event = mod_state.write().events_in.pop_front();
            if let Some(next_event) = next_event {
                if next_event.len() > len as usize {
                    error!("Serialized event is too long");
                    return 0;
                }

                let arr = Uint8Array::from(&next_event[..]);

                if let Some(memory) = memory.read().as_ref() {
                    let wasm_memory = Uint8Array::new(&memory.buffer());
                    wasm_memory.set(&arr, ptr as u32); // CompileError: wasm validation error: at offset 4581242: unused values not explicitly dropped by end of block
                    next_event.len() as u32
                } else {
                    0
                }
            } else {
                0
            }
        }
    });

    link::<dyn FnMut(i32, u32, i32, u32) -> u32>(&host, "get_resource", {
        let mod_state = mod_state.clone();
        let memory = memory.clone();
        move |type_path_buffer, type_path_buffer_len, buffer_ptr, buffer_len| -> u32 {
            let memory_read = memory.read();
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

            let resource_bytes = mod_state.write().shared_resource_values.remove(type_path);

            let Some(resource_bytes) = resource_bytes else {
                return 0;
            };
            if resource_bytes.len() > buffer_len as usize {
                error!("Serialized event is too long");
                return 0;
            }
            let arr = Uint8Array::from(&resource_bytes[..]);
            let memory_arr = Uint8Array::new(&memory.buffer());
            memory_arr.set(&arr, buffer_ptr as u32); // CompileError: wasm validation error: at offset 4581242: unused values not explicitly dropped by end of block

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

    link::<dyn FnMut(i32) -> i32>(&wbp, "__wbindgen_cb_drop", {
        move |v| {
            let ret = unsafe { __wbindgen_cb_drop(v) };
            info!("__wbindgen_cb_drop: {v}, ret {v}");
            ret
        }
    });

    link::<dyn FnMut(i32, i32)>(&wbp, "__wbindgen_debug_string", {
        move |x, y| {
            info!("__wbindgen_debug_string: {x}, {y}");
            unsafe { __wbindgen_debug_string(x, y) };
        }
    });

    link::<dyn FnMut(i32, i32, i32) -> i32>(&wbp, "__wbindgen_describe_closure", {
        move |x, y, z| {
            info!("__wbindgen_describe_closure: {x}, {y}, {z}");
            // wasm-bindgen error
            //unsafe { __wbindgen_debug_string(x, y) };
            0
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
    link::<dyn FnMut(i32) -> i32>(&wbp, "__wbg_buffer_12d079cc21e14bdb", {
        move |v| {
            let ret = unsafe { __wbg_buffer_12d079cc21e14bdb(v) };
            info!("__wbg_buffer_12d079cc21e14bdb: {v}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32, i32, i32) -> i32>(
        &wbp,
        "__wbg_newwithbyteoffsetandlength_aa4a17c33a06e5cb",
        {
            move |x, y, z| {
                let ret = unsafe { __wbg_newwithbyteoffsetandlength_aa4a17c33a06e5cb(x, y, z) };
                info!(
                    "__wbg_newwithbyteoffsetandlength_aa4a17c33a06e5cb: {x}, {y}, {z}, ret {ret}"
                );
                ret
            }
        },
    );

    link::<dyn FnMut(i32, i32)>(&wbp, "__wbg_randomFillSync_290977693942bf03", {
        move |x, y| {
            info!("__wbg_randomFillSync_290977693942bf03: {x}, {y}");
            unsafe { __wbg_randomFillSync_290977693942bf03(x, y) };
        }
    });

    link::<dyn FnMut(i32, i32, i32) -> i32>(&wbp, "__wbg_setTimeout_c172d5704ef82276", {
        move |x, y, z| {
            let ret = unsafe { __wbg_setTimeout_c172d5704ef82276(x, y, z) };
            info!("__wbg_setTimeout_c172d5704ef82276: {x}, {y}, {z}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32, i32)>(&wbp, "__wbg_stack_658279fe44541cf6", {
        move |x, y| {
            info!("__wbg_stack_658279fe44541cf6: {x}, {y}");
            unsafe { __wbg_stack_658279fe44541cf6(x, y) };
        }
    });

    link::<dyn FnMut(i32, i32)>(&wbp, "__wbg_error_f851667af71bcfc6", {
        move |x, y| {
            info!("__wbg_error_f851667af71bcfc6: {x}, {y}");
            unsafe { __wbg_error_f851667af71bcfc6(x, y) };
        }
    });

    link::<dyn FnMut(i32, i32)>(&wbp, "__wbg_log_aba5996d9bde071f", {
        move |x, y| {
            info!("__wbg_log_aba5996d9bde071f: {x}, {y}");
            // unsafe { __wbg_log_aba5996d9bde071f(x, y) };
        }
    });

    link::<dyn FnMut(i32, i32)>(&wbp, "__wbg_log_c9486ca5d8e2cbe8", {
        move |x, y| {
            info!("__wbg_log_c9486ca5d8e2cbe8: {x}, {y}");
            unsafe { __wbg_log_c9486ca5d8e2cbe8(x, y) };
        }
    });

    link::<dyn FnMut(i32, i32)>(&wbp, "__wbg_mark_40e050a77cc39fea", {
        move |x, y| {
            info!("__wbg_mark_40e050a77cc39fea: {x}, {y}");
            unsafe { __wbg_mark_40e050a77cc39fea(x, y) };
        }
    });

    link::<dyn FnMut(i32, i32, i32, i32)>(&wbp, "__wbg_measure_aa7a73f17813f708", {
        move |a, b, c, d| {
            info!("__wbg_measure_aa7a73f17813f708: {a}, {b}, {c}, {d}");
            unsafe { __wbg_measure_aa7a73f17813f708(a, b, c, d) };
        }
    });

    link::<dyn FnMut(i32) -> i32>(&wbp, "__wbg_instanceof_Window_f401953a2cf86220", {
        move |v| {
            let ret = unsafe { __wbg_instanceof_Window_f401953a2cf86220(v) };
            info!("__wbg_instanceof_Window_f401953a2cf86220: {v}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32) -> i32>(&wbp, "__wbg_performance_eeefc685c9bc38b4", {
        move |v| {
            let ret = unsafe { __wbg_performance_eeefc685c9bc38b4(v) };
            info!("__wbg_performance_eeefc685c9bc38b4: {v}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut() -> i32>(&wbp, "__wbg_new_abda76e883ba8a5f", {
        move || {
            let ret = unsafe { __wbg_new_abda76e883ba8a5f() };
            info!("__wbg_new_abda76e883ba8a5f: ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32) -> f64>(&wbp, "__wbg_now_e0d8ec93dd25766a", {
        move |v| {
            // Don't log this function, it's quite spammy
            unsafe { __wbg_now_e0d8ec93dd25766a(v) }
        }
    });

    link::<dyn FnMut(i32, i32, i32) -> i32>(&wbp, "__wbg_subarray_a1f73cd4b5b42fe1", {
        move |x, y, z| {
            let ret = unsafe { __wbg_subarray_a1f73cd4b5b42fe1(x, y, z) };
            info!("__wbg_subarray_a1f73cd4b5b42fe1: {x}, {y}, {z}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32, i32)>(&wbp, "__wbg_getRandomValues_260cc23a41afad9a", {
        move |x, y| {
            info!("__wbg_getRandomValues_260cc23a41afad9a: {x}, {y}");
            unsafe { __wbg_getRandomValues_260cc23a41afad9a(x, y) };
        }
    });

    link::<dyn FnMut(i32) -> i32>(&wbp, "__wbg_new_63b92bc8671ed464", {
        move |v| {
            let ret = unsafe { __wbg_new_63b92bc8671ed464(v) };
            info!("__wbg_new_63b92bc8671ed464: {v}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32, i32, i32)>(&wbp, "__wbg_set_a47bac70306a19a7", {
        move |x, y, z| {
            info!("__wbg_set_a47bac70306a19a7: {x}, {y}, {z}");
            unsafe { __wbg_set_a47bac70306a19a7(x, y, z) };
        }
    });

    link::<dyn FnMut(i32) -> i32>(&wbp, "__wbg_crypto_566d7465cdbb6b7a", {
        move |v| {
            let ret = unsafe { __wbg_crypto_566d7465cdbb6b7a(v) };
            info!("__wbg_crypto_566d7465cdbb6b7a: {v}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32) -> i32>(&wbp, "__wbg_process_dc09a8c7d59982f6", {
        move |v| {
            let ret = unsafe { __wbg_process_dc09a8c7d59982f6(v) };
            info!("__wbg_process_dc09a8c7d59982f6: {v}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32) -> i32>(&wbp, "__wbg_versions_d98c6400c6ca2bd8", {
        move |v| {
            let ret = unsafe { __wbg_versions_d98c6400c6ca2bd8(v) };
            info!("__wbg_versions_d98c6400c6ca2bd8: {v}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32) -> i32>(&wbp, "__wbg_node_caaf83d002149bd5", {
        move |v| {
            let ret = unsafe { __wbg_node_caaf83d002149bd5(v) };
            info!("__wbg_node_caaf83d002149bd5: {v}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut() -> i32>(&wbp, "__wbg_require_94a9da52636aacbf", {
        move || {
            let ret = unsafe { __wbg_require_94a9da52636aacbf() };
            info!("__wbg_require_94a9da52636aacbf: ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32, i32, i32) -> i32>(&wbp, "__wbg_call_b3ca7c6051f9bec1", {
        move |x, y, z| {
            let ret = unsafe { __wbg_call_b3ca7c6051f9bec1(x, y, z) };
            info!("__wbg_call_b3ca7c6051f9bec1: {x}, {y}, {z}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32) -> i32>(&wbp, "__wbg_msCrypto_0b84745e9245cdf6", {
        move |v| {
            let ret = unsafe { __wbg_msCrypto_0b84745e9245cdf6(v) };
            info!("__wbg_msCrypto_0b84745e9245cdf6: {v}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32) -> i32>(&wbp, "__wbg_newwithlength_e9b4878cebadb3d3", {
        move |v| {
            let ret = unsafe { __wbg_newwithlength_e9b4878cebadb3d3(v) };
            info!("__wbg_newwithlength_e9b4878cebadb3d3: {v}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut() -> i32>(&wbp, "__wbg_self_ce0dbfc45cf2f5be", {
        move || {
            let ret = unsafe { __wbg_self_ce0dbfc45cf2f5be() };
            info!("__wbg_self_ce0dbfc45cf2f5be: ret {ret}");
            ret
        }
    });

    link::<dyn FnMut() -> i32>(&wbp, "__wbg_window_c6fb939a7f436783", {
        move || {
            let ret = unsafe { __wbg_window_c6fb939a7f436783() };
            info!("__wbg_window_c6fb939a7f436783: ret {ret}");
            ret
        }
    });

    link::<dyn FnMut() -> i32>(&wbp, "__wbg_globalThis_d1e6af4856ba331b", {
        move || {
            let ret = unsafe { __wbg_globalThis_d1e6af4856ba331b() };
            info!("__wbg_globalThis_d1e6af4856ba331b: ret {ret}");
            ret
        }
    });

    link::<dyn FnMut() -> i32>(&wbp, "__wbg_global_207b558942527489", {
        move || {
            let ret = unsafe { __wbg_global_207b558942527489() };
            info!("__wbg_global_207b558942527489: ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32, i32) -> i32>(&wbp, "__wbg_newnoargs_e258087cd0daa0ea", {
        move |x, y| {
            let ret = unsafe { __wbg_newnoargs_e258087cd0daa0ea(x, y) };
            info!("__wbg_newnoargs_e258087cd0daa0ea: {x}, {y}, ret {ret}");
            ret
        }
    });

    link::<dyn FnMut(i32, i32) -> i32>(&wbp, "__wbg_call_27c0f87801dedf93", {
        move |x, y| {
            let ret = unsafe { __wbg_call_27c0f87801dedf93(x, y) };
            info!("__wbg_call_27c0f87801dedf93: {x}, {y}, ret {ret}");
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
