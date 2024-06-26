use std::collections::VecDeque;
use std::sync::Arc;

use bevy::utils::{HashMap, Instant};

/// Internal mod state
pub struct ModState {
    /// Time when the mod was loaded
    pub startup_time: Instant,

    /// Pointer given to us in `store_app`
    pub app_ptr: i32,

    /// Events that have been sent to the mod
    pub events_in: VecDeque<Arc<[u8]>>,

    /// Events that have been sent to the host
    pub events_out: Vec<Box<[u8]>>,

    /// Resources that have changed since the last update
    pub shared_resource_values: HashMap<&'static str, Arc<[u8]>>,
}
