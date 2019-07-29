// Copyright 2018 The Kepler Developers
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! tests for wallet restore
#[macro_use]
extern crate log;
extern crate kepler_wallet_controller as wallet;
extern crate kepler_wallet_impls as impls;
extern crate kepler_wallet_libwallet as libwallet;

use kepler_wallet_util::kepler_keychain as keychain;

use self::keychain::{ExtKeychain, Identifier, Keychain};
use self::libwallet::{AcctPathMapping, InitTxArgs, Slate};
use impls::test_framework::{self, LocalWalletClient};
use std::fs;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::Duration;

#[macro_use]
mod common;
use common::{create_wallet_proxy, setup};

fn restore_wallet(base_dir: &'static str, wallet_dir: &str) -> Result<(), libwallet::Error> {
	let source_seed = format!("{}/{}/wallet_data/wallet.seed", base_dir, wallet_dir);
	let dest_wallet_name = format!("{}_restore", wallet_dir);
	let dest_dir = format!("{}/{}/wallet_data", base_dir, dest_wallet_name);

	let mut wallet_proxy = create_wallet_proxy(base_dir);
	create_wallet_and_add!(
		client,
		wallet,
		base_dir,
		&dest_wallet_name,
		None,
		&mut wallet_proxy
	);
	// close created wallet
	let mut w_lock = wallet.lock();
	let lc = w_lock.lc_provider()?;
	lc.close_wallet(None)?;

	let dest_seed = format!("{}/wallet.seed", dest_dir);
	println!("Source: {}, Dest: {}", source_seed, dest_seed);
	fs::copy(source_seed, dest_seed)?;

	// reopen with new seed
	open_wallet_and_add!(
		client,
		wallet,
		&base_dir,
		&dest_wallet_name,
		&mut wallet_proxy
	);

	// Set the wallet proxy listener running
	let wp_running = wallet_proxy.running.clone();
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// perform the restore and update wallet info
	wallet::controller::owner_single_use(wallet.clone(), |api| {
		let _ = api.restore()?;
		let _ = api.retrieve_summary_info(true, 1)?;
		Ok(())
	})?;

	wp_running.store(false, Ordering::Relaxed);
	//thread::sleep(Duration::from_millis(1000));

	Ok(())
}

fn compare_wallet_restore(
	base_dir: &'static str,
	wallet_dir: &str,
	account_path: &Identifier,
) -> Result<(), libwallet::Error> {
	let restore_name = format!("{}_restore", wallet_dir);
	let mut wallet_proxy = create_wallet_proxy(base_dir);

	open_wallet_and_add!(
		client,
		wallet_source,
		&base_dir,
		&wallet_dir,
		&mut wallet_proxy
	);
	open_wallet_and_add!(
		client,
		wallet_dest,
		&base_dir,
		&restore_name,
		&mut wallet_proxy
	);

	{
		wallet_inst!(wallet_source, w);
		w.set_parent_key_id(account_path.clone());
	}

	{
		wallet_inst!(wallet_dest, w);
		w.set_parent_key_id(account_path.clone());
	}

	// Set the wallet proxy listener running
	let wp_running = wallet_proxy.running.clone();
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	let mut src_info: Option<libwallet::WalletInfo> = None;
	let mut dest_info: Option<libwallet::WalletInfo> = None;

	let mut src_txs: Option<Vec<libwallet::TxLogEntry>> = None;
	let mut dest_txs: Option<Vec<libwallet::TxLogEntry>> = None;

	let mut src_accts: Option<Vec<AcctPathMapping>> = None;
	let mut dest_accts: Option<Vec<AcctPathMapping>> = None;

	// Overall wallet info should be the same
	wallet::controller::owner_single_use(wallet_source.clone(), |api| {
		src_info = Some(api.retrieve_summary_info(true, 1)?.1);
		src_txs = Some(api.retrieve_txs(true, None, None)?.1);
		src_accts = Some(api.accounts()?);
		Ok(())
	})?;

	wallet::controller::owner_single_use(wallet_dest.clone(), |api| {
		dest_info = Some(api.retrieve_summary_info(true, 1)?.1);
		dest_txs = Some(api.retrieve_txs(true, None, None)?.1);
		dest_accts = Some(api.accounts()?);
		Ok(())
	})?;

	// Info should all be the same
	assert_eq!(src_info, dest_info);

	// Net differences in TX logs should be the same
	let src_sum: i64 = src_txs
		.clone()
		.unwrap()
		.iter()
		.map(|t| t.amount_credited as i64 - t.amount_debited as i64)
		.sum();

	let dest_sum: i64 = dest_txs
		.clone()
		.unwrap()
		.iter()
		.map(|t| t.amount_credited as i64 - t.amount_debited as i64)
		.sum();

	assert_eq!(src_sum, dest_sum);

	// Number of created accounts should be the same
	assert_eq!(
		src_accts.as_ref().unwrap().len(),
		dest_accts.as_ref().unwrap().len()
	);

	wp_running.store(false, Ordering::Relaxed);
	//thread::sleep(Duration::from_millis(1000));

	Ok(())
}

/// Build up 2 wallets, perform a few transactions on them
/// Then attempt to restore them in separate directories and check contents are the same
fn setup_restore(test_dir: &'static str) -> Result<(), libwallet::Error> {
	setup(test_dir);

	// Create a new proxy to simulate server and wallet responses
	let mut wallet_proxy = create_wallet_proxy(test_dir);
	let chain = wallet_proxy.chain.clone();

	create_wallet_and_add!(
		client1,
		wallet1,
		test_dir,
		"wallet1",
		None,
		&mut wallet_proxy
	);
	create_wallet_and_add!(
		client2,
		wallet2,
		test_dir,
		"wallet2",
		None,
		&mut wallet_proxy
	);

	// wallet 2 will use another account
	wallet::controller::owner_single_use(wallet2.clone(), |api| {
		api.create_account_path("account1")?;
		api.create_account_path("account2")?;
		Ok(())
	})?;

	// Default wallet 2 to listen on that account
	{
		wallet_inst!(wallet2, w);
		w.set_parent_key_id_by_name("account1")?;
	}

	// Another wallet
	create_wallet_and_add!(
		client3,
		wallet3,
		test_dir,
		"wallet3",
		None,
		&mut wallet_proxy
	);

	// Set the wallet proxy listener running
	let wp_running = wallet_proxy.running.clone();
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// mine a few blocks
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), 10, false);

	// assert wallet contents
	// and a single use api for a send command
	let amount = 60_000_000_000;
	let mut slate = Slate::blank(1);
	wallet::controller::owner_single_use(wallet1.clone(), |sender_api| {
		// note this will increment the block count as part of the transaction "Posting"
		let args = InitTxArgs {
			src_acct_name: None,
			amount: amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		let slate_i = sender_api.init_send_tx(args)?;
		slate = client1.send_tx_slate_direct("wallet2", &slate_i)?;
		sender_api.tx_lock_outputs(&slate, 0)?;
		slate = sender_api.finalize_tx(&slate)?;
		sender_api.post_tx(&slate.tx, false)?;
		Ok(())
	})?;

	// mine a few more blocks
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), 3, false);

	// Send some to wallet 3
	wallet::controller::owner_single_use(wallet1.clone(), |sender_api| {
		// note this will increment the block count as part of the transaction "Posting"
		let args = InitTxArgs {
			src_acct_name: None,
			amount: amount * 2,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		let slate_i = sender_api.init_send_tx(args)?;
		slate = client1.send_tx_slate_direct("wallet3", &slate_i)?;
		sender_api.tx_lock_outputs(&slate, 0)?;
		slate = sender_api.finalize_tx(&slate)?;
		sender_api.post_tx(&slate.tx, false)?;
		Ok(())
	})?;

	// mine a few more blocks
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet3.clone(), 10, false);

	// Wallet3 to wallet 2
	wallet::controller::owner_single_use(wallet3.clone(), |sender_api| {
		// note this will increment the block count as part of the transaction "Posting"
		let args = InitTxArgs {
			src_acct_name: None,
			amount: amount * 3,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		let slate_i = sender_api.init_send_tx(args)?;
		slate = client3.send_tx_slate_direct("wallet2", &slate_i)?;
		sender_api.tx_lock_outputs(&slate, 0)?;
		slate = sender_api.finalize_tx(&slate)?;
		sender_api.post_tx(&slate.tx, false)?;
		Ok(())
	})?;

	// Another listener account on wallet 2
	{
		wallet_inst!(wallet2, w);
		w.set_parent_key_id_by_name("account2")?;
	}

	// mine a few more blocks
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), 2, false);

	// Wallet3 to wallet 2 again (to another account)
	wallet::controller::owner_single_use(wallet3.clone(), |sender_api| {
		// note this will increment the block count as part of the transaction "Posting"
		let args = InitTxArgs {
			src_acct_name: None,
			amount: amount * 3,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		let slate_i = sender_api.init_send_tx(args)?;
		slate = client3.send_tx_slate_direct("wallet2", &slate_i)?;
		sender_api.tx_lock_outputs(&slate, 0)?;
		slate = sender_api.finalize_tx(&slate)?;
		sender_api.post_tx(&slate.tx, false)?;
		Ok(())
	})?;

	// mine a few more blocks
	let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), 5, false);

	// update everyone
	wallet::controller::owner_single_use(wallet1.clone(), |api| {
		let _ = api.retrieve_summary_info(true, 1)?;
		Ok(())
	})?;
	wallet::controller::owner_single_use(wallet2.clone(), |api| {
		let _ = api.retrieve_summary_info(true, 1)?;
		Ok(())
	})?;
	wallet::controller::owner_single_use(wallet3.clone(), |api| {
		let _ = api.retrieve_summary_info(true, 1)?;
		Ok(())
	})?;

	wp_running.store(false, Ordering::Relaxed);

	Ok(())
}

fn perform_restore(test_dir: &'static str) -> Result<(), libwallet::Error> {
	restore_wallet(test_dir, "wallet1")?;
	compare_wallet_restore(
		test_dir,
		"wallet1",
		&ExtKeychain::derive_key_id(2, 0, 0, 0, 0),
	)?;
	restore_wallet(test_dir, "wallet2")?;
	compare_wallet_restore(
		test_dir,
		"wallet2",
		&ExtKeychain::derive_key_id(2, 0, 0, 0, 0),
	)?;
	compare_wallet_restore(
		test_dir,
		"wallet2",
		&ExtKeychain::derive_key_id(2, 1, 0, 0, 0),
	)?;
	compare_wallet_restore(
		test_dir,
		"wallet2",
		&ExtKeychain::derive_key_id(2, 2, 0, 0, 0),
	)?;
	restore_wallet(test_dir, "wallet3")?;
	compare_wallet_restore(
		test_dir,
		"wallet3",
		&ExtKeychain::derive_key_id(2, 0, 0, 0, 0),
	)?;
	Ok(())
}

#[test]
fn wallet_restore() {
	let test_dir = "test_output/wallet_restore";
	if let Err(e) = setup_restore(test_dir) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
	if let Err(e) = perform_restore(test_dir) {
		panic!("Libwallet Error: {} - {}", e, e.backtrace().unwrap());
	}
	// let logging finish
	thread::sleep(Duration::from_millis(200));
}
