// Copyright 2023 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: Apache-2.0

use crate::config::old_config_v1_1_13::OldConfigV1_1_13;
use crate::config::old_config_v1_1_19::ConfigV1_1_19;
use crate::{
    config::{BaseClientConfig, Config},
    error::NetworkRequesterError,
};
use clap::{CommandFactory, Parser, Subcommand};
use log::{error, info};
use nym_bin_common::build_information::BinaryBuildInformation;
use nym_bin_common::completions::{fig_generate, ArgShell};

mod init;
mod run;

lazy_static::lazy_static! {
    pub static ref PRETTY_BUILD_INFORMATION: String =
        BinaryBuildInformation::new(env!("CARGO_PKG_VERSION")).pretty_print();
}

// Helper for passing LONG_VERSION to clap
fn pretty_build_info_static() -> &'static str {
    &PRETTY_BUILD_INFORMATION
}

#[derive(Parser)]
#[clap(author = "Nymtech", version, about, long_version = pretty_build_info_static())]
pub(crate) struct Cli {
    /// Path pointing to an env file that configures the client.
    #[clap(short, long)]
    pub(crate) config_env_file: Option<std::path::PathBuf>,

    #[clap(subcommand)]
    command: Commands,
}

#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Initialize a network-requester. Do this first!
    Init(init::Init),

    /// Run the network requester with the provided configuration and optionally override
    /// parameters.
    Run(run::Run),

    /// Generate shell completions
    Completions(ArgShell),

    /// Generate Fig specification
    GenerateFigSpec,
}

// Configuration that can be overridden.
pub(crate) struct OverrideConfig {
    nym_apis: Option<Vec<url::Url>>,
    fastmode: bool,
    no_cover: bool,
    nyxd_urls: Option<Vec<url::Url>>,
    enabled_credentials_mode: Option<bool>,
}

pub(crate) fn override_config(config: Config, args: OverrideConfig) -> Config {
    config
        .with_base(
            BaseClientConfig::with_high_default_traffic_volume,
            args.fastmode,
        )
        .with_base(BaseClientConfig::with_disabled_cover_traffic, args.no_cover)
        .with_optional_base_custom_env(
            BaseClientConfig::with_custom_nym_apis,
            args.nym_apis,
            nym_network_defaults::var_names::NYM_API,
            nym_config::parse_urls,
        )
        .with_optional_base_custom_env(
            BaseClientConfig::with_custom_nyxd,
            args.nyxd_urls,
            nym_network_defaults::var_names::NYXD,
            nym_config::parse_urls,
        )
        .with_optional_base(
            BaseClientConfig::with_disabled_credentials,
            args.enabled_credentials_mode.map(|b| !b),
        )
}

pub(crate) async fn execute(args: Cli) -> Result<(), NetworkRequesterError> {
    let bin_name = "nym-network-requester";

    match &args.command {
        Commands::Init(m) => init::execute(m).await?,
        Commands::Run(m) => run::execute(m).await?,
        Commands::Completions(s) => s.generate(&mut Cli::command(), bin_name),
        Commands::GenerateFigSpec => fig_generate(&mut Cli::command(), bin_name),
    }
    Ok(())
}

fn try_upgrade_v1_1_13_config(id: &str) -> Result<bool, NetworkRequesterError> {
    use nym_config::legacy_helpers::nym_config::MigrationNymConfig;

    // explicitly load it as v1.1.13 (which is incompatible with the next step, i.e. 1.1.19)
    let Ok(old_config) = OldConfigV1_1_13::load_from_file(id) else {
        // if we failed to load it, there might have been nothing to upgrade
        // or maybe it was an even older file. in either way. just ignore it and carry on with our day
        return Ok(false);
    };
    info!("It seems the client is using <= v1.1.13 config template.");
    info!("It is going to get updated to the current specification.");

    let updated_step1: ConfigV1_1_19 = old_config.into();
    let updated: Config = updated_step1.into();

    updated.save_to_default_location()?;
    Ok(true)
}

fn try_upgrade_v1_1_19_config(id: &str) -> Result<bool, NetworkRequesterError> {
    use nym_config::legacy_helpers::nym_config::MigrationNymConfig;

    // explicitly load it as v1.1.19 (which is incompatible with the current one, i.e. +1.1.20)
    let Ok(old_config) = ConfigV1_1_19::load_from_file(id) else {
        // if we failed to load it, there might have been nothing to upgrade
        // or maybe it was an even older file. in either way. just ignore it and carry on with our day
        return Ok(false);
    };

    info!("It seems the client is using <= v1.1.19 config template.");
    info!("It is going to get updated to the current specification.");

    let updated: Config = old_config.into();
    updated.save_to_default_location()?;
    Ok(true)
}

fn try_upgrade_config(id: &str) -> Result<(), NetworkRequesterError> {
    let upgraded = try_upgrade_v1_1_13_config(id)?;
    if !upgraded {
        try_upgrade_v1_1_19_config(id)?;
    }

    Ok(())
}

fn try_load_current_config(id: &str) -> Result<Config, NetworkRequesterError> {
    try_upgrade_config(id)?;

    let config = match Config::read_from_default_path(id) {
        Ok(cfg) => cfg,
        Err(err) => {
            error!("Failed to load config for {id}. Are you sure you have run `init` before? (Error was: {err})");
            return Err(NetworkRequesterError::FailedToLoadConfig(id.to_string()));
        }
    };

    if !config.validate() {
        return Err(NetworkRequesterError::ConfigValidationFailure);
    }

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn verify_cli() {
        Cli::command().debug_assert();
    }
}
