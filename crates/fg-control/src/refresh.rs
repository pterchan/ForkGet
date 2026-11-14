//! Import controlled snapshots and retire only unpinned generations.

use fg_meta::{Metadata, RefreshGeneration};

use crate::{
    ControlError,
    bootstrap::{self, Import},
    grants::NativeRoles,
    native::NativeOptions,
    seed::{self, SeedVersion},
};

pub(crate) struct Request {
    pub version: SeedVersion,
    pub cooldown_seconds: u32,
}

pub(crate) async fn run(
    metadata: &Metadata,
    options: &NativeOptions,
    roles: &NativeRoles,
    request: Request,
) -> Result<i64, ControlError> {
    let version = request.version;
    let _guard = metadata.lock_bootstrap().await?;
    let mut native = options.connect().await?;
    bootstrap::recover(metadata, &mut native, roles).await?;
    let engine = native.engine();
    let catalog = metadata.native_catalog(engine.name()).await?;
    let seeds = seed::tables(engine, version);
    let generation = metadata
        .allocate_refresh(RefreshGeneration {
            engine: engine.name(),
            snapshot: &version.name(),
            tables: &seeds,
            cooldown_seconds: request.cooldown_seconds,
        })
        .await?;
    bootstrap::install(
        metadata,
        &mut native,
        roles,
        Import {
            generation: &generation,
            seeds: &seeds,
            version,
            catalog: &catalog,
        },
    )
    .await?;
    // An uncertain metadata commit is reconciled on the next operator command.
    metadata
        .switch_generation(generation.id, engine.name())
        .await?;
    Ok(generation.id)
}

pub(crate) async fn retire(
    metadata: &Metadata,
    options: &NativeOptions,
    roles: &NativeRoles,
    id: i64,
) -> Result<(), ControlError> {
    let _guard = metadata.lock_bootstrap().await?;
    let Some(generation) = metadata
        .retirement_candidate(id, options.engine().name())
        .await?
    else {
        return Ok(());
    };
    let mut native = options.connect().await?;
    bootstrap::remove_generation(&mut native, &generation, roles).await?;
    metadata.complete_retirement(id).await?;
    Ok(())
}
