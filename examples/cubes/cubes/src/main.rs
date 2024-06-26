use bevy::prelude::*;
use bevy_wasm::prelude::*;
use cubes_protocol::{HostMessage, ModMessage, PROTOCOL_VERSION};

fn main() {
    App::new()
        .add_plugins(DefaultPlugins)
        .add_plugins(WasmPlugin::<HostMessage, ModMessage>::new(PROTOCOL_VERSION))
        .add_systems(Startup, (insert_mods, setup))
        .add_systems(Update, update_cubes_from_mods)
        .run();
}

fn insert_mods(mut commands: Commands, asset_server: Res<AssetServer>) {
    commands.spawn(WasmMod {
        wasm: asset_server.load("mod_with_bevy.wasm"),
    });
    commands.spawn(WasmMod {
        wasm: asset_server.load("mod_without_bevy.wasm"),
    });
}

/// set up a simple 3D scene
fn setup(
    mut commands: Commands,
    mut meshes: ResMut<Assets<Mesh>>,
    mut materials: ResMut<Assets<StandardMaterial>>,
) {
    // plane
    commands.spawn(PbrBundle {
        mesh: meshes.add(Mesh::from(Plane3d {
            normal: Direction3d::new_unchecked(Vec3 {
                x: 0.0,
                y: 1.0,
                z: 0.0,
            }),
        })),
        material: materials.add(Color::rgb(0.3, 0.5, 0.3)),
        ..default()
    });
    commands.spawn(PointLightBundle {
        point_light: PointLight {
            intensity: 1500.0,
            shadows_enabled: true,
            ..default()
        },
        transform: Transform::from_xyz(4.0, 8.0, 4.0),
        ..default()
    });
    // camera
    commands.spawn(Camera3dBundle {
        transform: Transform::from_xyz(-2.0, 3.5, 5.0)
            .looking_at(Vec3::new(0.0, 1.0, 0.0), Vec3::Y),
        ..default()
    });
}

fn update_cubes_from_mods(
    mut commands: Commands,
    mut meshes: ResMut<Assets<Mesh>>,
    mut materials: ResMut<Assets<StandardMaterial>>,
    mut events_out: EventReader<ModMessage>, // GET messages FROM mods
    mut events_in: EventWriter<HostMessage>, // SEND messages TO mods
    mut query: Query<&mut Transform>,
) {
    for event in events_out.read() {
        match event {
            ModMessage::MoveCube { entity_id, x, y, z } => {
                if let Ok(mut transform) = query.get_mut(Entity::from_raw(*entity_id)) {
                    transform.translation = Vec3::new(*x, *y, *z);
                }
            }
            ModMessage::SpawnCube { mod_state, color } => {
                info!("Spawning cube from mod {:x}!", mod_state);
                let entity_id = commands
                    .spawn(PbrBundle {
                        mesh: meshes.add(Mesh::from(Cuboid {
                            half_size: Vec3::splat(0.25),
                        })),
                        material: materials.add(Color::rgb(color.0, color.1, color.2)),
                        transform: Transform::from_xyz(0.0, 0.5, 0.0),
                        ..default()
                    })
                    .id()
                    .index();
                events_in.send(HostMessage::SpawnedCube {
                    mod_state: *mod_state,
                    entity_id,
                });
            }
        }
    }
}
