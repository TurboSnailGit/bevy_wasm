//! Implements loader for a custom asset type.

use bevy::asset::{Asset, AssetLoader, AsyncReadExt, LoadContext};
use bevy::reflect::TypePath;
use bevy::utils::BoxedFuture;
use serde::Deserialize;
use thiserror::Error;

#[derive(Debug, Deserialize, Asset, TypePath)]
pub struct WasmAsset {
    pub bytes: Vec<u8>,
}

#[derive(Default)]
pub struct WasmAssetLoader;

#[derive(Error, Debug)]
pub enum WasmAssetLoaderError {}

impl AssetLoader for WasmAssetLoader {
    type Asset = WasmAsset;
    type Settings = ();
    type Error = WasmAssetLoaderError;

    fn extensions(&self) -> &[&str] {
        &["wasm"]
    }

    fn load<'a>(
        &'a self,
        reader: &'a mut bevy::asset::io::Reader,
        _settings: &'a Self::Settings,
        _load_context: &'a mut LoadContext,
    ) -> BoxedFuture<'a, Result<Self::Asset, Self::Error>> {
        Box::pin(async move {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes).await.unwrap();

            Ok(WasmAsset { bytes })
        })
    }
}
