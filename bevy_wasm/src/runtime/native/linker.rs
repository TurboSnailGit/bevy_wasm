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
            let type_path: String =
                unsafe { std::str::from_utf8_unchecked(type_path_data).to_string() };

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

    // Because some bevy dependencies uses wasm-bindgen
    // __wbindgen_placeholder__::__wbindgen_*

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

    // https://github.com/WebAssembly/WASI/blob/main/legacy/preview1/docs.md#-random_getbuf-pointeru8-buf_len-size---result-errno
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "random_get",
        |mut caller: Caller<'_, ModState>, buf: i32, buf_len: i32| -> i32 {
            let memory = match caller.get_export("memory") {
                Some(Extern::Memory(mem)) => mem,
                _ => panic!("random_get: failed to find host memory"),
            };

            let Some(buf_slice) = memory
                .data_mut(&mut caller)
                .get_mut(buf as u32 as usize..)
                .and_then(|arr| arr.get_mut(..buf_len as usize))
            else {
                error!("random_get: Failed to get data from memory");
                return 0;
            };

            // Fill buffer with random data.
            match getrandom::getrandom(buf_slice) {
                Ok(_) => 0, // 0 indicates success in WASI.
                Err(err) => {
                    error!("random_get: getrandom {err}");
                    1
                }
            }
        },
    )?;

    // https://github.com/WebAssembly/WASI/blob/main/legacy/preview1/docs.md#-fd_writefd-fd-iovs-ciovec_array---resultsize-errno
    // fd : A file descriptor handle.
    // iovs : List of scatter/gather vectors from which to retrieve data
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "fd_write",
        |fd: i32, fd_len: i32, iovs: i32, iovs_len: i32| -> i32 {
            info!("fd_write: fd: {fd}, size {fd_len}. iovs {iovs} size {iovs_len}");
            0
        },
    )?;

    // https://github.com/WebAssembly/WASI/blob/main/legacy/preview1/docs.md#-sched_yield---result-errno
    // sched_yield() -> Result<(), errno>
    // Temporarily yield execution of the calling thread. Note: This is similar to sched_yield in POSIX.
    linker.func_wrap("wasi_snapshot_preview1", "sched_yield", || -> i32 {
        info!("sched_yield");
        0
    })?;

    // https://github.com/WebAssembly/WASI/blob/main/legacy/preview1/docs.md#-environ_getenviron-pointerpointeru8-environ_buf-pointeru8---result-errno
    //  environ_get(environ: Pointer<Pointer<u8>>, environ_buf: Pointer<u8>) -> Result<(), errno>
    // Read environment variable data.
    // The sizes of the buffers should match that returned by environ_sizes_get.
    // Key/value pairs are expected to be joined with =s, and terminated with \0s.
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "environ_get",
        |environ: i32, environ_buf: i32| -> i32 {
            info!("environ_get environ {environ} size {environ_buf}");
            0
        },
    )?;

    // https://github.com/WebAssembly/WASI/blob/main/legacy/preview1/docs.md#-environ_sizes_get---resultsize-size-errno
    // environ_sizes_get() -> Result<(size, size), errno>
    // Return environment variable data sizes.
    linker.func_wrap(
        "wasi_snapshot_preview1",
        "environ_sizes_get",
        |a: i32, b: i32| -> i32 {
            info!("environ_sizes_get {a} {b}");
            0
        },
    )?;

    // https://github.com/WebAssembly/WASI/blob/main/legacy/preview1/docs.md#-proc_exitrval-exitcode
    // proc_exit(rval: exitcode)
    // Terminate the process normally.
    // An exit code of 0 indicates successful termination of the program.
    // The meanings of other values is dependent on the environment.
    linker.func_wrap("wasi_snapshot_preview1", "proc_exit", |rval: i32| {
        info!("proc_exit {rval}");
    })?;

    linker.func_wrap(
        "__wbindgen_placeholder__",
        "__wbindgen_describe",
        |v: i32| {
            info!("__wbindgen_describe: {v}");
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
