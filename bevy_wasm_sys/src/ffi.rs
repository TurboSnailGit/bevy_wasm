//! FFI declarations for communicating with the host.

#![allow(missing_docs)]

use std::ffi::c_void;

use bevy::app::App;

#[link(wasm_import_module = "host")]
extern "C" {
    pub fn store_app(app: *const c_void);
    pub fn console_info(msg: *const u8, len: usize);
    pub fn console_warn(msg: *const u8, len: usize);
    pub fn console_error(msg: *const u8, len: usize);
    pub fn send_serialized_event(event: *const u8, len: usize);
    pub fn get_next_event(event: *const u8, len: usize) -> usize;
    /// Nanoseconds since the mod was loaded
    pub fn get_time_since_startup() -> u64;
    pub fn get_protocol_version() -> u64;
    pub fn get_resource(
        type_path_buffer: *const u8,
        type_path_buffer_len: usize,
        buffer: *const u8,
        buffer_len: usize,
    ) -> usize;
}

/// This function is called by the host every frame.
///
/// # Safety
///
/// `app` is assumed to be a valid pointer to an [`App`].
#[no_mangle]
pub unsafe extern "C" fn update(app: *mut c_void) {
    if app.is_null() {
        return;
    }

    let app = app as *mut App;
    (*app).update();
}
