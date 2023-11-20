// Copyright 2021 - Nym Technologies SA <contact@nymtech.net>
// SPDX-License-Identifier: Apache-2.0

use crate::context::SigningClient;
use clap::Parser;
use cosmwasm_std::Uint128;
use log::info;
use nym_mixnet_contract_common::{MixNodeCostParams, Percent};
use nym_validator_client::nyxd::contract_traits::MixnetSigningClient;
use nym_validator_client::nyxd::CosmWasmCoin;

#[derive(Debug, Parser)]
pub struct Args {
    #[clap(
        long,
        help = "input your profit margin as follows; (so it would be 10, rather than 0.1)"
    )]
    pub profit_margin_percent: Option<u8>,

    #[clap(
        long,
        help = "operating cost in current DENOMINATION (so it would be 'unym', rather than 'nym')"
    )]
    pub interval_operating_cost: Option<u128>,
}

pub async fn update_cost_params(args: Args, client: SigningClient) {
    let denom = client.current_chain_details().mix_denom.base.as_str();

    let cost_params = MixNodeCostParams {
        profit_margin_percent: Percent::from_percentage_value(
            args.profit_margin_percent.unwrap_or(10) as u64,
        )
        .unwrap(),
        interval_operating_cost: CosmWasmCoin {
            denom: denom.into(),
            amount: Uint128::new(args.interval_operating_cost.unwrap_or(40_000_000)),
        },
    };

    info!("Starting mixnode params updating!");
    let res = client
        .update_mixnode_cost_params(cost_params, None)
        .await
        .expect("failed to update cost params");

    info!("Cost params result: {:?}", res)
}
