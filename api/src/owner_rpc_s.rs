// Copyright 2019 The Grin Developers
//
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

//! JSON-RPC Stub generation for the Owner API
use uuid::Uuid;

use crate::config::{TorConfig, WalletConfig};
use crate::core::core::Transaction;
use crate::core::global;
use crate::keychain::{Identifier, Keychain};
use crate::libwallet::slate_versions::v3::TransactionV3;
use crate::libwallet::{
	AcctPathMapping, ErrorKind, InitTxArgs, IssueInvoiceTxArgs, NodeClient, NodeHeightResult,
	OutputCommitMapping, Slate, SlateVersion, StatusMessage, TxLogEntry, VersionedSlate,
	WalletInfo, WalletLCProvider,
};
use crate::util::logger::LoggingConfig;
use crate::util::secp::key::{PublicKey, SecretKey};
use crate::util::{static_secp_instance, ZeroingString};
use crate::{ECDHPubkey, Owner, PubAddress, Token};
use easy_jsonrpc_mw;
use rand::thread_rng;
use std::time::Duration;

/// Public definition used to generate Owner jsonrpc api.
/// Secure version containing wallet lifecycle functions. All calls to this API must be encrypted.
/// See [`init_secure_api`](#tymethod.init_secure_api) for details of secret derivation
/// and encryption.

#[easy_jsonrpc_mw::rpc]
pub trait OwnerRpcS {
	/**
	Networked version of [Owner::accounts](struct.Owner.html#method.accounts).

	# Json rpc example

	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "accounts",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				{
					"label": "default",
					"path": "0200000000000000000000000000000000"
				}
			]
		},
		"id": 1
	}
	# "#
	# , true, 4, false, false, false);
	```
	*/
	fn accounts(&self, token: Token) -> Result<Vec<AcctPathMapping>, ErrorKind>;

	/**
	Networked version of [Owner::create_account_path](struct.Owner.html#method.create_account_path).

	# Json rpc example

	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "create_account_path",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"label": "account1"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": "0200000001000000000000000000000000"
		},
		"id": 1
	}
	# "#
	# ,true, 4, false, false, false);
	```
	 */
	fn create_account_path(&self, token: Token, label: &String) -> Result<Identifier, ErrorKind>;

	/**
	Networked version of [Owner::set_active_account](struct.Owner.html#method.set_active_account).

	# Json rpc example

	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "set_active_account",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"label": "default"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		},
		"id": 1
	}
	# "#
	# , true, 4, false, false, false);
	```
	 */
	fn set_active_account(&self, token: Token, label: &String) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::retrieve_outputs](struct.Owner.html#method.retrieve_outputs).

	# Json rpc example

	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_outputs",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"include_spent": false,
			"refresh_from_node": true,
			"tx_id": null
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				true,
				[
					{
						"commit": "09016c5a3376e054e20402797e4367605e30d032eda4a8752fbe05ffd8659a7fa8",
						"output": {
							"commit": "09016c5a3376e054e20402797e4367605e30d032eda4a8752fbe05ffd8659a7fa8",
							"height": "1",
							"is_coinbase": true,
							"key_id": "0300000000000000000000000000000000",
							"lock_height": "4",
							"mmr_index": null,
							"n_child": 0,
							"root_key_id": "0200000000000000000000000000000000",
							"status": "Unspent",
							"tx_log_entry": 0,
							"value": "1000000000000"
						}
					},
					{
						"commit": "09924c88f0fe4d11ecc655b55aa54ca372260423287cc6e70c5a6062b7bee5cf24",
						"output": {
							"commit": "09924c88f0fe4d11ecc655b55aa54ca372260423287cc6e70c5a6062b7bee5cf24",
							"height": "2",
							"is_coinbase": true,
							"key_id": "0300000000000000000000000100000000",
							"lock_height": "5",
							"mmr_index": null,
							"n_child": 1,
							"root_key_id": "0200000000000000000000000000000000",
							"status": "Unspent",
							"tx_log_entry": 1,
							"value": "1000000000000"
						}
					}
				]
			]
		}
	}
	# "#
	# , true, 2, false, false, false);
	```
	*/
	fn retrieve_outputs(
		&self,
		token: Token,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), ErrorKind>;

	/**
	Networked version of [Owner::retrieve_txs](struct.Owner.html#method.retrieve_txs).

	# Json rpc example

	```
		# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "retrieve_txs",
			"params": {
				"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"refresh_from_node": true,
				"tx_id": null,
				"tx_slate_id": null
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
		"id": 1,
		"jsonrpc": "2.0",
	  "result": {
		"Ok": [
		  true,
		  [
			{
			  "amount_credited": "1000000000000",
			  "amount_debited": "0",
			  "confirmation_ts": "2019-01-15T16:01:26Z",
			  "confirmed": true,
			  "creation_ts": "2019-01-15T16:01:26Z",
			  "fee": null,
			  "id": 0,
			  "kernel_excess": "089f1cd58cfa4487280819836b0da9eb18299d7b07c0e1f93f6f93c2a58045af19",
			  "kernel_lookup_min_height": 1,
			  "messages": null,
			  "num_inputs": 0,
			  "num_outputs": 1,
			  "parent_key_id": "0200000000000000000000000000000000",
			  "stored_tx": null,
			  "ttl_cutoff_height": null,
			  "tx_slate_id": null,
			  "payment_proof": null,
			  "tx_type": "ConfirmedCoinbase"
			},
			{
			  "amount_credited": "1000000000000",
			  "amount_debited": "0",
			  "confirmation_ts": "2019-01-15T16:01:26Z",
			  "confirmed": true,
			  "creation_ts": "2019-01-15T16:01:26Z",
			  "fee": null,
			  "id": 1,
			  "kernel_excess": "08a0b5fb47ab3efbc3fd70d639914cfc1c734c0c904090060b63ea597a345cef63",
			  "kernel_lookup_min_height": 2,
			  "messages": null,
			  "num_inputs": 0,
			  "num_outputs": 1,
			  "parent_key_id": "0200000000000000000000000000000000",
			  "stored_tx": null,
			  "ttl_cutoff_height": null,
			  "payment_proof": null,
			  "tx_slate_id": null,
			  "tx_type": "ConfirmedCoinbase"
			}
		  ]
		]
	  }
	}
	# "#
	# , true, 2, false, false, false);
	```
	*/

	fn retrieve_txs(
		&self,
		token: Token,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), ErrorKind>;

	/**
	Networked version of [Owner::retrieve_summary_info](struct.Owner.html#method.retrieve_summary_info).

	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_summary_info",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"refresh_from_node": true,
			"minimum_confirmations": 1
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
	"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": [
				true,
				{
					"amount_awaiting_confirmation": "0",
					"amount_awaiting_finalization": "0",
					"amount_currently_spendable": "1000000000000",
					"amount_immature": "3000000000000",
					"amount_locked": "0",
					"last_confirmed_height": "4",
					"minimum_confirmations": "1",
					"total": "4000000000000"
				}
			]
		}
	}
	# "#
	# ,true, 4, false, false, false);
	```
	 */

	fn retrieve_summary_info(
		&self,
		token: Token,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), ErrorKind>;

	/**
		Networked version of [Owner::init_send_tx](struct.Owner.html#method.init_send_tx).

	```
		# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "init_send_tx",
			"params": {
				"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"args": {
					"src_acct_name": null,
					"amount": "6000000000",
					"minimum_confirmations": 2,
					"max_outputs": 500,
					"num_change_outputs": 1,
					"selection_strategy_is_use_all": true,
					"message": "my message",
					"target_slate_version": null,
					"payment_proof_recipient_address": "d03c09e9c19bb74aa9ea44e0fe5ae237a9bf40bddf0941064a80913a4459c8bb",
					"ttl_blocks": null,
					"send_args": null
				}
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
	  "id": 1,
	  "jsonrpc": "2.0",
	  "result": {
		"Ok": {
		  "amount": "6000000000",
		  "fee": "8000000",
		  "height": "4",
		  "id": "0436430c-2b02-624c-2032-570501212b00",
		  "lock_height": "0",
			"ttl_cutoff_height": null,
		  "num_participants": 2,
			"payment_proof": {
		"receiver_address": "d03c09e9c19bb74aa9ea44e0fe5ae237a9bf40bddf0941064a80913a4459c8bb",
		"receiver_signature": null,
		"sender_address": "32cdd63928854f8b2628b1dce4626ddcdf35d56cb7cfdf7d64cca5822b78d4d3"
	  },
		  "participant_data": [
			{
			  "id": "0",
			  "message": "my message",
			  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b3da1f57a16d431e0a62789190addda10aa6025b7d2b37adec814bf6bd3335e5c",
			  "part_sig": null,
			  "public_blind_excess": "03868af206cf66e21b89a1e579826e376383ee5e0b55aa7bb3fde13235ae673b7a",
			  "public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
			}
		  ],
		  "tx": {
			"body": {
			  "inputs": [
				{
				  "commit": "09016c5a3376e054e20402797e4367605e30d032eda4a8752fbe05ffd8659a7fa8",
				  "features": "Coinbase"
				}
			  ],
			  "kernels": [
				{
				  "excess": "000000000000000000000000000000000000000000000000000000000000000000",
				  "excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				  "features": "Plain",
				  "fee": "8000000",
				  "lock_height": "0"
				}
			  ],
			  "outputs": [
				{
				  "commit": "08b38e1ffb83c44006f927e6f3214c9f1f4afff5cea4767a3bc26b671f1d303d3b",
				  "features": "Plain",
				  "proof": "c988992bbb0b961eb55a11c914b484c8e5f02cb76b918e0bc0aace54d82b220e8366dd095d572c2f1b43ad9ebbd5eadf0e1f9a4d5eb246daa38b2080b13889250c54f2c88c6faf3370468e0f237b5c3f7dc5c9c1273a6e9c25daaad1719fd49cf88605815b2d62fb61aa93959d370913077a05d144816a03496bf215a87e1df105aba4fac252c9fd539c898002056efe101305ebef283754716cde030a3ee86150f3502f72b66b5f12c63aba96b4297b07a234d73d3f4288dcca420cc88ea7dda2c81d94433b9ebad67bbd1f7874b582a453581f3bec21f3227c64f02a241f198d3e298a7fc773f4d6a0340d351545b949775a618bf16c1bcab7d5c428c0a99e4b1b57c604a7d2dd0ffb95c4465816fd91978d7677d52c2b30da4d1d0e903c1f62e6788edf9390fae3727eefd00f5685c82a47d5526229274237c78f0b4e913a7799d7eee30e7b09c17d590402c792adf84c07e030d98ad683fc2b010329501df6f10337f1a02d5317d666223810936fb0874e12ae04bac0d55978eac78307412c86356cf2984e7d8024e60d88b1b75ff3002a1d1baf9152e23917b5c8a2f3cf376957fd669f92638140565f014c0fc3a178bdddd0f633e9de84d037e7e9333abd76024ca2f23ed943402ae05b13c2fe51fd5cbed60f31e89165e9cda2f0b732044f5a499d1e90f877dd69d61b06e660a5a238050343510d00905122a9f7c3626d2e903be8bdb1cdd4ac4fedce3b586bd83563de6b44b901c027b6c295e5ed6211c2fe81d32c3de06abc4ac40220d5c1915f287cddd3dbcade7921677227b216cabb4032ea623cfc2d94a8465f539354a731a7905af771eff2b8d99c3509150e60d9f0913f083b00842cb7ad5f9bfa467e6033539bb9b7b610d5748c4deedcb54ca1540f8e1daa2953122ae6bd2e97f9d9d56650cc2c4d45387e38bd783142cc76b66c"
				}
			  ]
			},
			"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
		  },
		  "version_info": {
				"orig_version": 3,
				"version": 3,
				"block_header_version": 2
		  }
		}
	  }
	}
		# "#
		# ,true, 4, false, false, false);
	```
	*/

	fn init_send_tx(&self, token: Token, args: InitTxArgs) -> Result<VersionedSlate, ErrorKind>;

	/**
		Networked version of [Owner::issue_invoice_tx](struct.Owner.html#method.issue_invoice_tx).

	```
		# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "issue_invoice_tx",
			"params": {
				"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"args": {
					"amount": "6000000000",
					"message": "Please give me your keplers",
					"dest_acct_name": null,
					"target_slate_version": null
				}
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
			"id": 1,
			"jsonrpc": "2.0",
			"result": {
				"Ok": {
					"amount": "6000000000",
					"fee": "0",
					"height": "4",
					"id": "0436430c-2b02-624c-2032-570501212b00",
					"lock_height": "0",
					"ttl_cutoff_height": null,
					"num_participants": 2,
					"payment_proof": null,
					"participant_data": [
						{
							"id": "1",
							"message": "Please give me your keplers",
							"message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bec94661d0552993642accf52cf45d16f854de5509b8d2c602ead1d8bdd160825",
							"part_sig": null,
							"public_blind_excess": "028e95921cc0d5be5922362265d352c9bdabe51a9e1502a3f0d4a10387f1893f40",
							"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
						}
					],
					"tx": {
						"body": {
							"inputs": [],
							"kernels": [
								{
									"excess": "000000000000000000000000000000000000000000000000000000000000000000",
									"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
									"features": "Plain",
									"fee": "0",
									"lock_height": "0"
								}
							],
							"outputs": [
								{
									"commit": "09cf47204446c326e361a1a92f34b174deff732daaedb80d7339fbe3db5ca2f6ba",
									"features": "Plain",
									"proof": "b368448efb3bfae95e7f18381883d64cbc9f01390e9c677d5d9f3523df43754dd174811768b7ffcafbfb284ae7413bdf56640ecb06918a5c38a5dae6cb33baff099c7cca6b052e07f915faecedee50a11ceaf41a7809bd33b51e22306ddf42620f7118133a418802f6e98222a8f3683cf3d5a5314155d0bf5f2e8be68e81ebe049ece23b0135d7b878c1ecebbf03de69fb8cbaf5f9611a430ae3083f71e0a74db8899b0083123a9e1924db8d340fdcc0bba4816afc613a0c6622fa89a84f31982cd4298a3b4c4de9d5f67800f48c6b37b4b49fb527290ec92f1551f4570abe42ac6ac42b05e3579b33533b784061ccbd2507af419079c3ea846f1af1aa2bfb04837166c60eab8207fed9000d3c2f5166e655e9220051223b90fb5751becc8a18cf10fb43cbc1cdeb8d0f11f5d0eb9dffdd4480abd69a49737f526b41b78f3c00bd7ef10f6ad3d8704f9ac6e79196c57b315a37265ca561fa333733e9c9275a2a4dc703b509b3ff11e6d983dd43a06566c82832ae0da9c8e9759038c6c86b30a05dd5cacc42c10fad496dee8cf63127233ae0bd27c766aed7448ebd7afbaa35c5491795fca7441b5373c4912e99ffbded6c7082d67f0b688f5af662be375f76699a69fcccb9c1c1841056fb4b6ec3f1c4dc40f032675fc2c87bab58e3375dac567533c4d0e3f1521e561029e231f3675368bde5817d177bd9c20b8cd7eb3b94260b0794f207bb33b9b8157518dbac8d725352b27ffa0e2aaa95d04592a87a6ee68deebaf1c51183704bea8ddd4298616fa353bc411936eafa1b31cc667a41a13a2d1a91db48464ea26c39ee1f68e67cbdd652165b040b43df2c80beda6af53dfbe0aa3aeb06c1887f9be83ed19b4b7094ba35700dad3ea4090594e662ae2a1c276b969751ab6d5d49a2c727d7ee2c80ffdc3d1ba040a20269b9bfc45930f467dbb43f64"
								}
							]
						},
						"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
					},
					"version_info": {
						"orig_version": 3,
						"version": 3,
						"block_header_version": 2
					}
				}
			}
		}
		# "#
		# ,true, 4, false, false, false);
	```
	*/

	fn issue_invoice_tx(
		&self,
		token: Token,
		args: IssueInvoiceTxArgs,
	) -> Result<VersionedSlate, ErrorKind>;

	/**
		 Networked version of [Owner::process_invoice_tx](struct.Owner.html#method.process_invoice_tx).

	```
		# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "process_invoice_tx",
			"params": {
				"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
				"slate": {
					"amount": "6000000000",
					"fee": "0",
					"height": "4",
					"id": "0436430c-2b02-624c-2032-570501212b00",
					"lock_height": "0",
					"ttl_cutoff_height": null,
					"num_participants": 2,
					"payment_proof": null,
					"participant_data": [
						{
							"id": "1",
							"message": "Please give me your keplers",
							"message_sig": "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fd2599ab38942986602e943f684a85992893a6d34367dc7cc2b403a5dcfcdbcd9",
							"part_sig": null,
							"public_blind_excess": "028e95921cc0d5be5922362265d352c9bdabe51a9e1502a3f0d4a10387f1893f40",
							"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
						}
					],
					"tx": {
						"body": {
							"inputs": [],
							"kernels": [
								{
									"excess": "000000000000000000000000000000000000000000000000000000000000000000",
									"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
									"features": "Plain",
									"fee": "0",
									"lock_height": "0"
								}
							],
							"outputs": [
								{
									"commit": "09cf47204446c326e361a1a92f34b174deff732daaedb80d7339fbe3db5ca2f6ba",
									"features": "Plain",
									"proof": "8f511614315626b5f39224482351d766f5a8ef136262befc050d839be8479b0a13470cd88f4436346d213d83847a4055c6e0ac63681556470349a1aab47034a3015eb64d8163955998e2dd4165dd24386b1e279974b05deb5d46ba2bc321f7000c0784f8f10690605ffe717119d045e02b141ed12d8fc6d20930483a8af889ef533495eb442fcff36d98ebc104f13fc645c28431b3296e4a11f7c991ff97f9abbc2f8886762d7f29fdacb31d52c6850e6ccf5386117d89e8ea4ca3071c56c218dd5d3bcd65f6c06ed9f51f848507ca1d594f41796d1cf99f68a5c3f0c5dd9873602284cff31269b102fcc6c68607565faaf0adb04ed4ff3ea5d41f3b5235ac6cb90e4046c808c9c48c27172c891b20085c56a99913ef47fd8b3dc4920cef50534b9319a7cefe0df10a0206a634ac837e11da92df83ff58b1a14de81313400988aa48b946fcbe1b81f0e79e13f7c6c639b1c10983b424bda08d0ce593a20f1f47e0aa01473e7144f116b76d9ebc60599053d8f1542d60747793d99064e51fce8f8866390325d48d6e8e3bbdbc1822c864303451525c6cb4c6902f105a70134186fb32110d8192fc2528a9483fc8a4001f4bdeab1dd7b3d1ccb9ae2e746a78013ef74043f0b2436f0ca49627af1768b7c791c669bd331fd18c16ef88ad0a29861db70f2f76f3e74fde5accb91b73573e31333333223693d6fbc786e740c085e4fc6e7bde0a3f54e9703f816c54f012d3b1f41ec4d253d9337af61e7f1f1383bd929421ac346e3d2771dfee0b60503b33938e7c83eb37af3b6bf66041a3519a2b4cb557b34e3b9afcf95524f9a011425a34d32e7b6e9f255291094930acae26e8f7a1e4e6bc405d0f88e919f354f3ba85356a34f1aba5f7da1fad88e2692f4129cc1fb80a2122b2d996c6ccf7f08d8248e511d92af9ce49039de728848a2dc74101f4e94a"
								}
							]
						},
						"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
					},
					"version_info": {
						"orig_version": 3,
						"version": 3,
						"block_header_version": 2
					}
				},
				"args": {
					"src_acct_name": null,
					"amount": "0",
					"minimum_confirmations": 2,
					"max_outputs": 500,
					"num_change_outputs": 1,
					"selection_strategy_is_use_all": true,
					"message": "Ok, here are your keplers",
					"target_slate_version": null,
					"payment_proof_recipient_address": null,
					"ttl_blocks": null,
					"send_args": null
				}
			},
			"id": 1
		}
		# "#
		# ,
		# r#"
		{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"amount": "6000000000",
				"fee": "8000000",
				"height": "4",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"lock_height": "0",
				"ttl_cutoff_height": null,
				"num_participants": 2,
				"payment_proof": null,
				"participant_data": [
					{
						"id": "1",
						"message": "Please give me your keplers",
						"message_sig": "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fd2599ab38942986602e943f684a85992893a6d34367dc7cc2b403a5dcfcdbcd9",
						"part_sig": null,
						"public_blind_excess": "028e95921cc0d5be5922362265d352c9bdabe51a9e1502a3f0d4a10387f1893f40",
						"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					},
					{
						"id": "0",
						"message": "Ok, here are your keplers",
						"message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bf156f4bd16be7634339e3f6fde97e21c75cd89631b8ff0335ecb667cc30e0e8f",
						"part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b2297ecee6b49e478703502fe8eca62fb80092c71ae63c602e7e998f4b37316f3",
						"public_blind_excess": "0361af54e62115d72393cfa15c66b5af798f2121519deac1efa5b709815be58c80",
						"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					}
				],
				"tx": {
					"body": {
						"inputs": [
							{
								"commit": "09016c5a3376e054e20402797e4367605e30d032eda4a8752fbe05ffd8659a7fa8",
								"features": "Coinbase"
							}
						],
						"kernels": [
							{
								"excess": "000000000000000000000000000000000000000000000000000000000000000000",
								"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
								"features": "Plain",
								"fee": "8000000",
								"lock_height": "0"
							}
						],
						"outputs": [
							{
								"commit": "08b38e1ffb83c44006f927e6f3214c9f1f4afff5cea4767a3bc26b671f1d303d3b",
								"features": "Plain",
								"proof": "c988992bbb0b961eb55a11c914b484c8e5f02cb76b918e0bc0aace54d82b220e8366dd095d572c2f1b43ad9ebbd5eadf0e1f9a4d5eb246daa38b2080b13889250c54f2c88c6faf3370468e0f237b5c3f7dc5c9c1273a6e9c25daaad1719fd49cf88605815b2d62fb61aa93959d370913077a05d144816a03496bf215a87e1df105aba4fac252c9fd539c898002056efe101305ebef283754716cde030a3ee86150f3502f72b66b5f12c63aba96b4297b07a234d73d3f4288dcca420cc88ea7dda2c81d94433b9ebad67bbd1f7874b582a453581f3bec21f3227c64f02a241f198d3e298a7fc773f4d6a0340d351545b949775a618bf16c1bcab7d5c428c0a99e4b1b57c604a7d2dd0ffb95c4465816fd91978d7677d52c2b30da4d1d0e903c1f62e6788edf9390fae3727eefd00f5685c82a47d5526229274237c78f0b4e913a7799d7eee30e7b09c17d590402c792adf84c07e030d98ad683fc2b010329501df6f10337f1a02d5317d666223810936fb0874e12ae04bac0d55978eac78307412c86356cf2984e7d8024e60d88b1b75ff3002a1d1baf9152e23917b5c8a2f3cf376957fd669f92638140565f014c0fc3a178bdddd0f633e9de84d037e7e9333abd76024ca2f23ed943402ae05b13c2fe51fd5cbed60f31e89165e9cda2f0b732044f5a499d1e90f877dd69d61b06e660a5a238050343510d00905122a9f7c3626d2e903be8bdb1cdd4ac4fedce3b586bd83563de6b44b901c027b6c295e5ed6211c2fe81d32c3de06abc4ac40220d5c1915f287cddd3dbcade7921677227b216cabb4032ea623cfc2d94a8465f539354a731a7905af771eff2b8d99c3509150e60d9f0913f083b00842cb7ad5f9bfa467e6033539bb9b7b610d5748c4deedcb54ca1540f8e1daa2953122ae6bd2e97f9d9d56650cc2c4d45387e38bd783142cc76b66c"
							},
							{
								"commit": "09cf47204446c326e361a1a92f34b174deff732daaedb80d7339fbe3db5ca2f6ba",
								"features": "Plain",
								"proof": "8f511614315626b5f39224482351d766f5a8ef136262befc050d839be8479b0a13470cd88f4436346d213d83847a4055c6e0ac63681556470349a1aab47034a3015eb64d8163955998e2dd4165dd24386b1e279974b05deb5d46ba2bc321f7000c0784f8f10690605ffe717119d045e02b141ed12d8fc6d20930483a8af889ef533495eb442fcff36d98ebc104f13fc645c28431b3296e4a11f7c991ff97f9abbc2f8886762d7f29fdacb31d52c6850e6ccf5386117d89e8ea4ca3071c56c218dd5d3bcd65f6c06ed9f51f848507ca1d594f41796d1cf99f68a5c3f0c5dd9873602284cff31269b102fcc6c68607565faaf0adb04ed4ff3ea5d41f3b5235ac6cb90e4046c808c9c48c27172c891b20085c56a99913ef47fd8b3dc4920cef50534b9319a7cefe0df10a0206a634ac837e11da92df83ff58b1a14de81313400988aa48b946fcbe1b81f0e79e13f7c6c639b1c10983b424bda08d0ce593a20f1f47e0aa01473e7144f116b76d9ebc60599053d8f1542d60747793d99064e51fce8f8866390325d48d6e8e3bbdbc1822c864303451525c6cb4c6902f105a70134186fb32110d8192fc2528a9483fc8a4001f4bdeab1dd7b3d1ccb9ae2e746a78013ef74043f0b2436f0ca49627af1768b7c791c669bd331fd18c16ef88ad0a29861db70f2f76f3e74fde5accb91b73573e31333333223693d6fbc786e740c085e4fc6e7bde0a3f54e9703f816c54f012d3b1f41ec4d253d9337af61e7f1f1383bd929421ac346e3d2771dfee0b60503b33938e7c83eb37af3b6bf66041a3519a2b4cb557b34e3b9afcf95524f9a011425a34d32e7b6e9f255291094930acae26e8f7a1e4e6bc405d0f88e919f354f3ba85356a34f1aba5f7da1fad88e2692f4129cc1fb80a2122b2d996c6ccf7f08d8248e511d92af9ce49039de728848a2dc74101f4e94a"
							}
						]
					},
					"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
				},
				"version_info": {
					"orig_version": 3,
					"version": 3,
					"block_header_version": 2
				}
			}
		}
	}
	# "#
	# ,true, 4, false, false, false);
	```
	*/

	fn process_invoice_tx(
		&self,
		token: Token,
		slate: VersionedSlate,
		args: InitTxArgs,
	) -> Result<VersionedSlate, ErrorKind>;

	/**
	Networked version of [Owner::tx_lock_outputs](struct.Owner.html#method.tx_lock_outputs).

	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "tx_lock_outputs",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"slate": {
				"amount": "6000000000",
				"fee": "8000000",
				"height": "4",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"lock_height": "4",
				"ttl_cutoff_height": null,
				"num_participants": 2,
				"payment_proof": null,
				"participant_data": [
				{
					"id": "0",
					"message": "my message",
					"message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b1d4c1358be398f801eb90d933774b5218fa7e769b11c4c640402253353656f75",
					"part_sig": null,
					"public_blind_excess": "034b4df2f0558b73ea72a1ca5c4ab20217c66bbe0829056fca7abe76888e9349ee",
					"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				}
				],
				"tx": {
					"body": {
						"inputs": [
						{
							"commit": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
							"features": "Coinbase"
						}
						],
						"kernels": [
						{
							"excess": "000000000000000000000000000000000000000000000000000000000000000000",
							"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							"features": "HeightLocked",
							"fee": "8000000",
							"lock_height": "4"
						}
						],
						"outputs": [
						{
							"commit": "094be57c91787fc2033d5d97fae099f1a6ddb37ea48370f1a138f09524c767fdd3",
							"features": "Plain",
							"proof": "2a42e9e902b70ce44e1fccb14de87ee0a97100bddf12c6bead1b9c5f4eb60300f29c13094fa12ffeee238fb4532b18f6b61cf51b23c1c7e1ad2e41560dc27edc0a2b9e647a0b3e4e806fced5b65e61d0f1f5197d3e2285c632d359e27b6b9206b2caffea4f67e0c7a2812e7a22c134b98cf89bd43d9f28b8bec25cce037a0ac5b1ae8f667e54e1250813a5263004486b4465ad4e641ab2b535736ea26535a11013564f08f483b7dab1c2bcc3ee38eadf2f7850eff7e3459a4bbabf9f0cf6c50d0c0a4120565cd4a2ce3e354c11721cd695760a24c70e0d5a0dfc3c5dcd51dfad6de2c237a682f36dc0b271f21bb3655e5333016aaa42c2efa1446e5f3c0a79ec417c4d30f77556951cb0f05dbfafb82d9f95951a9ea241fda2a6388f73ace036b98acce079f0e4feebccc96290a86dcc89118a901210b245f2d114cf94396e4dbb461e82aa26a0581389707957968c7cdc466213bb1cd417db207ef40c05842ab67a01a9b96eb1430ebc26e795bb491258d326d5174ad549401059e41782121e506744af8af9d8e493644a87d613600888541cbbe538c625883f3eb4aa3102c5cfcc25de8e97af8927619ce6a731b3b8462d51d993066b935b0648d2344ad72e4fd70f347fbd81041042e5ea31cc7b2e3156a920b80ecba487b950ca32ca95fae85b759c936246ecf441a9fdd95e8fee932d6782cdec686064018c857efc47fb4b2a122600d5fdd79af2486f44df7e629184e1c573bc0a9b3feb40b190ef2861a1ab45e2ac2201b9cd42e495deea247269820ed32389a2810ad6c0f9a296d2a2d9c54089fed50b7f5ecfcd33ab9954360e1d7f5598c32128cfcf2a1d8bf14616818da8a5343bfa88f0eedf392e9d4ab1ace1b60324129cd4852c2e27813a9cf71a6ae6229a4fcecc1a756b3e664c5f50af333082616815a3bec8fc0b75b8e4e767d719"
						}
						]
					},
					"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
				},
				"version_info": {
					"orig_version": 3,
					"version": 3,
					"block_header_version": 2
				}
			},
			"participant_id": 0
		}
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"Ok": null
		}
	}
	# "#
	# ,true, 5 ,true, false, false);

	```
	 */
	fn tx_lock_outputs(
		&self,
		token: Token,
		slate: VersionedSlate,
		participant_id: usize,
	) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::finalize_tx](struct.Owner.html#method.finalize_tx).

	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "finalize_tx",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"slate": {
				"version_info": {
					"version": 3,
					"orig_version": 3,
					"block_header_version": 2
				},
				"num_participants": 2,
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"payment_proof": null,
				"tx": {
					"offset": "d202964900000000d302964900000000d402964900000000d502964900000000",
					"body": {
						"inputs": [
							{
								"features": "Coinbase",
								"commit": "09016c5a3376e054e20402797e4367605e30d032eda4a8752fbe05ffd8659a7fa8"
							},
							{
								"features": "Coinbase",
								"commit": "09924c88f0fe4d11ecc655b55aa54ca372260423287cc6e70c5a6062b7bee5cf24"
							}
						],
						"outputs": [
							{
								"features": "Plain",
								"commit": "08daa3f55556f7f66ef0633bbee5ccd0b670488395faa38fcf85ad180608e2e948",
								"proof": "07cd4b1775d3a383661370a28b158b6af378ee586b7e5a03801e7201359f993ece12cc351c3a9dcda00790276abc509708500a6b9da951387342ac5e6728ad6f021fb14f5e3616c05d9ae8025eacdeab7e3f2f296f78efabd602188e5f06df7e42f89a46c5fc2b17dbcee762ed4c6fa5bcebfaa478279f6f17c0d6bd5403c9193b99e7228fcde547a095a2b571a698fd16cda3b0d568ff86919215361c6a3f75721d5413422d859c21938c3da43ffb902e049c17ce7c68363ffa726e0de15df546ba9c0f4744d5ff5652d4fc4ba04457d657606fc9a05234bad28a8c69118e0d0c190bda9f54a0c19b16ab84bd54805f37013e729a0a83964d37100a0836f9f4d5a9aca320606e65f99301f8a9bfd00aff3634f7cc3569360a000ba01a28a9e0f304d82c9071204884a06fad0322e0c2fa213ba68cdfb4e6752f31f6b854842a9d4ecf666a6f0fb4b298cec7b17dd1aa6e6f873e2f138512505beebe39db6db5426400e0f2700bbc877c0c1989fa258fda5996b984f510d03a8b863eea8d8ca589eadd218fc945945d16704f4b5d2e3eefc8a210e99d660a291c8a6545496bf3f98b7f156193e95eb468b729ec97c4b58d6b50495981975abbf6d8af494c971a72d306f68075d5477f255b9a028dce0935a6551c6fc2adb784dbaee8d5edcb1b4eb1a5519995948140066438c050cc790c57725e630d2f910f9f94fabd432a44b6c299442a1a7916d7147ebb7a71bc113a6f7f38f13646c2b9650ce2586cc958a8e921435116a51a6e7a27d7fb4721ec8feaafbfc64931abdd34f6f12ba1e08d1ebbe1abaf7d3967e4f781dd66b35312b3ad6e7af1a5c26c9aabe95a300c1864888ca6faa44a0396f5dca89ba60dc3bd6b35d0b2a1bd28b66a010158fe7607270210444935d7da32ebd8e24c91098c0607b70311963c1ffd782a9be91f6347912c5280"
							},
							{
								"features": "Plain",
								"commit": "08834fe21657d6e32dd33ce0a5dd53c7a70b25a36c37ef96a8bf3c70beb10a2ef9",
								"proof": "282d022ea9027d115d30745ad733cd22779a5287a821dc9701fed234da26d517fb2a06adb2de670f9d473312796184affa19161bf212f4d32613f4830aaa86940bf24a2afbc862d27107ed74ebb46365c38016125bca89e4ed3b8731efc5b41ef8de7cab090b82eed987b2ab645d411b4f95ae91e20e2714848637f1b22b5bb44c7f1801cb2a7544aa674a23f74481708d11d49d25e22d8b9fbe3d20562d64a2037849a55f7c8f548e9cd7a945c08fb2e06bbca70561a7a486df87018dd7c2e6bb578d5b3b8aad6a50c4cf675fcf74756915e37dbb62ac5d559599b86a3c14f3c9690a16eddb9cc0ace33eec8f5c3732cb355a7ec22cf6dcd2a983304abb44b911d47655f399570420971cbf7d1ae28fca1ffcbf2ca90b0f720091456de43f6719e9568ec584ef3016ad53edd46c369f445641d5393f1721789442bdd8e9363f4ddb90391dd3dedb67dc2c23747c526ff33bd8c5b4fb6cf6d8078f2fed81ea023ae100090eb56722eb5eb0ec899e92bc0b2ffbb5b04d6b9d7f1c813f2afbc76c02126e52cb2513fcae58aaf8cbf23ab93ce8dd43a63875ff1eff39caa1629c06370c797e443301e4c240ca1b3fb060e3606f559ccaba52fa238589145ec540b050183d19e8945139ddb998a94e3a21ca005c26ae4952b2d0d3e4b3788e1a00110d8b30db05bc6a55a92b4af64a26512c6257d1384bba7caae3b5ee25cf508d5b64e1929c5894ebaa8a505a8e2ce81af9588df482e3a3f07699acd6ee327b73281fea5bde559da05ba759e83ad53abbdcaf7d0804b89c17eca68a30d1e82eb0485138af1cf2df09e147de64cc2e6039efeb5ac1863a937d38ff6711275a940944688bcb86f4ca02c8aee3d069b902f7b262ebccc1f8bc78cdb5606617f58428b507df1fc477ee23a65b555325fd1f1387c16249b7845cd5b9550a9c6278da1c01db3ffb"
							}
						],
						"kernels": [
							{
								"features": "Plain",
								"fee": "7000000",
								"lock_height": "0",
								"excess": "000000000000000000000000000000000000000000000000000000000000000000",
								"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
							}
						]
					}
				},
				"amount": "1000000000000",
				"fee": "7000000",
				"height": "5",
				"lock_height": "0",
				"ttl_cutoff_height": null,
				"participant_data": [
					{
						"id": "0",
						"public_blind_excess": "03753c2cba849c4b14c70de681ff2e3fe1938bc3fe31562d7d0ebf4d5251a810e2",
						"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
						"part_sig": null,
						"message": null,
						"message_sig": null
					},
					{
						"id": "1",
						"public_blind_excess": "03c6970cd28d223932ff33146027d467194ca11269f6af01f843612a9eb76c5237",
						"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
						"part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b58575ed12586646519d74fe075a6de95c715e1ee930d864f4bd17b4ac95006d7",
						"message": null,
						"message_sig": null
					}
				]
			}
		}
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
		"Ok": {
				"amount": "1000000000000",
				"fee": "7000000",
				"height": "5",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"lock_height": "0",
				"ttl_cutoff_height": null,
				"num_participants": 2,
				"payment_proof": null,
				"participant_data": [
					{
						"id": "0",
						"message": null,
						"message_sig": null,
						"part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b9c0910d48ccca864577fa65b514bd6047acaa73e2f8ffdd05d847a8d61ed0cfd",
						"public_blind_excess": "03753c2cba849c4b14c70de681ff2e3fe1938bc3fe31562d7d0ebf4d5251a810e2",
						"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					},
					{
						"id": "1",
						"message": null,
						"message_sig": null,
						"part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b58575ed12586646519d74fe075a6de95c715e1ee930d864f4bd17b4ac95006d7",
						"public_blind_excess": "03c6970cd28d223932ff33146027d467194ca11269f6af01f843612a9eb76c5237",
						"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					}
				],
				"tx": {
					"body": {
						"inputs": [
							{
								"commit": "09016c5a3376e054e20402797e4367605e30d032eda4a8752fbe05ffd8659a7fa8",
								"features": "Coinbase"
							},
							{
								"commit": "09924c88f0fe4d11ecc655b55aa54ca372260423287cc6e70c5a6062b7bee5cf24",
								"features": "Coinbase"
							}
						],
						"kernels": [
							{
								"excess": "08781389569d5e37d4384104e7c34f20628ed7d534b09888d43f0d47c065eaf56a",
								"excess_sig": "66074d25a751c4743342c90ad8ead9454daa00d9b9aed29bca321036d16c4b4db31f38d525f43a0a35b6ad8ce01406e042e0882dc39c8320a955f6d72a3e13d4",
								"features": "Plain",
								"fee": "7000000",
								"lock_height": "0"
							}
						],
						"outputs": [
							{
								"commit": "08daa3f55556f7f66ef0633bbee5ccd0b670488395faa38fcf85ad180608e2e948",
								"features": "Plain",
								"proof": "07cd4b1775d3a383661370a28b158b6af378ee586b7e5a03801e7201359f993ece12cc351c3a9dcda00790276abc509708500a6b9da951387342ac5e6728ad6f021fb14f5e3616c05d9ae8025eacdeab7e3f2f296f78efabd602188e5f06df7e42f89a46c5fc2b17dbcee762ed4c6fa5bcebfaa478279f6f17c0d6bd5403c9193b99e7228fcde547a095a2b571a698fd16cda3b0d568ff86919215361c6a3f75721d5413422d859c21938c3da43ffb902e049c17ce7c68363ffa726e0de15df546ba9c0f4744d5ff5652d4fc4ba04457d657606fc9a05234bad28a8c69118e0d0c190bda9f54a0c19b16ab84bd54805f37013e729a0a83964d37100a0836f9f4d5a9aca320606e65f99301f8a9bfd00aff3634f7cc3569360a000ba01a28a9e0f304d82c9071204884a06fad0322e0c2fa213ba68cdfb4e6752f31f6b854842a9d4ecf666a6f0fb4b298cec7b17dd1aa6e6f873e2f138512505beebe39db6db5426400e0f2700bbc877c0c1989fa258fda5996b984f510d03a8b863eea8d8ca589eadd218fc945945d16704f4b5d2e3eefc8a210e99d660a291c8a6545496bf3f98b7f156193e95eb468b729ec97c4b58d6b50495981975abbf6d8af494c971a72d306f68075d5477f255b9a028dce0935a6551c6fc2adb784dbaee8d5edcb1b4eb1a5519995948140066438c050cc790c57725e630d2f910f9f94fabd432a44b6c299442a1a7916d7147ebb7a71bc113a6f7f38f13646c2b9650ce2586cc958a8e921435116a51a6e7a27d7fb4721ec8feaafbfc64931abdd34f6f12ba1e08d1ebbe1abaf7d3967e4f781dd66b35312b3ad6e7af1a5c26c9aabe95a300c1864888ca6faa44a0396f5dca89ba60dc3bd6b35d0b2a1bd28b66a010158fe7607270210444935d7da32ebd8e24c91098c0607b70311963c1ffd782a9be91f6347912c5280"
							},
							{
								"commit": "08834fe21657d6e32dd33ce0a5dd53c7a70b25a36c37ef96a8bf3c70beb10a2ef9",
								"features": "Plain",
								"proof": "282d022ea9027d115d30745ad733cd22779a5287a821dc9701fed234da26d517fb2a06adb2de670f9d473312796184affa19161bf212f4d32613f4830aaa86940bf24a2afbc862d27107ed74ebb46365c38016125bca89e4ed3b8731efc5b41ef8de7cab090b82eed987b2ab645d411b4f95ae91e20e2714848637f1b22b5bb44c7f1801cb2a7544aa674a23f74481708d11d49d25e22d8b9fbe3d20562d64a2037849a55f7c8f548e9cd7a945c08fb2e06bbca70561a7a486df87018dd7c2e6bb578d5b3b8aad6a50c4cf675fcf74756915e37dbb62ac5d559599b86a3c14f3c9690a16eddb9cc0ace33eec8f5c3732cb355a7ec22cf6dcd2a983304abb44b911d47655f399570420971cbf7d1ae28fca1ffcbf2ca90b0f720091456de43f6719e9568ec584ef3016ad53edd46c369f445641d5393f1721789442bdd8e9363f4ddb90391dd3dedb67dc2c23747c526ff33bd8c5b4fb6cf6d8078f2fed81ea023ae100090eb56722eb5eb0ec899e92bc0b2ffbb5b04d6b9d7f1c813f2afbc76c02126e52cb2513fcae58aaf8cbf23ab93ce8dd43a63875ff1eff39caa1629c06370c797e443301e4c240ca1b3fb060e3606f559ccaba52fa238589145ec540b050183d19e8945139ddb998a94e3a21ca005c26ae4952b2d0d3e4b3788e1a00110d8b30db05bc6a55a92b4af64a26512c6257d1384bba7caae3b5ee25cf508d5b64e1929c5894ebaa8a505a8e2ce81af9588df482e3a3f07699acd6ee327b73281fea5bde559da05ba759e83ad53abbdcaf7d0804b89c17eca68a30d1e82eb0485138af1cf2df09e147de64cc2e6039efeb5ac1863a937d38ff6711275a940944688bcb86f4ca02c8aee3d069b902f7b262ebccc1f8bc78cdb5606617f58428b507df1fc477ee23a65b555325fd1f1387c16249b7845cd5b9550a9c6278da1c01db3ffb"
							}
						]
					},
					"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
				},
				"version_info": {
					"orig_version": 3,
					"version": 3,
					"block_header_version": 2
				}
			}
		}
	}
	# "#
	# , true, 5, true, true, false);
	```
	 */
	fn finalize_tx(&self, token: Token, slate: VersionedSlate)
		-> Result<VersionedSlate, ErrorKind>;

	/**
	Networked version of [Owner::post_tx](struct.Owner.html#method.post_tx).

	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"method": "post_tx",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"tx": {
			"offset": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"body": {
				"inputs": [
					{
						"features": "Coinbase",
						"commit": "09016c5a3376e054e20402797e4367605e30d032eda4a8752fbe05ffd8659a7fa8"
					},
					{
						"features": "Coinbase",
						"commit": "09924c88f0fe4d11ecc655b55aa54ca372260423287cc6e70c5a6062b7bee5cf24"
					}
				],
				"outputs": [
					{
						"features": "Plain",
						"commit": "08daa3f55556f7f66ef0633bbee5ccd0b670488395faa38fcf85ad180608e2e948",
						"proof": "07cd4b1775d3a383661370a28b158b6af378ee586b7e5a03801e7201359f993ece12cc351c3a9dcda00790276abc509708500a6b9da951387342ac5e6728ad6f021fb14f5e3616c05d9ae8025eacdeab7e3f2f296f78efabd602188e5f06df7e42f89a46c5fc2b17dbcee762ed4c6fa5bcebfaa478279f6f17c0d6bd5403c9193b99e7228fcde547a095a2b571a698fd16cda3b0d568ff86919215361c6a3f75721d5413422d859c21938c3da43ffb902e049c17ce7c68363ffa726e0de15df546ba9c0f4744d5ff5652d4fc4ba04457d657606fc9a05234bad28a8c69118e0d0c190bda9f54a0c19b16ab84bd54805f37013e729a0a83964d37100a0836f9f4d5a9aca320606e65f99301f8a9bfd00aff3634f7cc3569360a000ba01a28a9e0f304d82c9071204884a06fad0322e0c2fa213ba68cdfb4e6752f31f6b854842a9d4ecf666a6f0fb4b298cec7b17dd1aa6e6f873e2f138512505beebe39db6db5426400e0f2700bbc877c0c1989fa258fda5996b984f510d03a8b863eea8d8ca589eadd218fc945945d16704f4b5d2e3eefc8a210e99d660a291c8a6545496bf3f98b7f156193e95eb468b729ec97c4b58d6b50495981975abbf6d8af494c971a72d306f68075d5477f255b9a028dce0935a6551c6fc2adb784dbaee8d5edcb1b4eb1a5519995948140066438c050cc790c57725e630d2f910f9f94fabd432a44b6c299442a1a7916d7147ebb7a71bc113a6f7f38f13646c2b9650ce2586cc958a8e921435116a51a6e7a27d7fb4721ec8feaafbfc64931abdd34f6f12ba1e08d1ebbe1abaf7d3967e4f781dd66b35312b3ad6e7af1a5c26c9aabe95a300c1864888ca6faa44a0396f5dca89ba60dc3bd6b35d0b2a1bd28b66a010158fe7607270210444935d7da32ebd8e24c91098c0607b70311963c1ffd782a9be91f6347912c5280"
					},
					{
						"features": "Plain",
						"commit": "08834fe21657d6e32dd33ce0a5dd53c7a70b25a36c37ef96a8bf3c70beb10a2ef9",
						"proof": "282d022ea9027d115d30745ad733cd22779a5287a821dc9701fed234da26d517fb2a06adb2de670f9d473312796184affa19161bf212f4d32613f4830aaa86940bf24a2afbc862d27107ed74ebb46365c38016125bca89e4ed3b8731efc5b41ef8de7cab090b82eed987b2ab645d411b4f95ae91e20e2714848637f1b22b5bb44c7f1801cb2a7544aa674a23f74481708d11d49d25e22d8b9fbe3d20562d64a2037849a55f7c8f548e9cd7a945c08fb2e06bbca70561a7a486df87018dd7c2e6bb578d5b3b8aad6a50c4cf675fcf74756915e37dbb62ac5d559599b86a3c14f3c9690a16eddb9cc0ace33eec8f5c3732cb355a7ec22cf6dcd2a983304abb44b911d47655f399570420971cbf7d1ae28fca1ffcbf2ca90b0f720091456de43f6719e9568ec584ef3016ad53edd46c369f445641d5393f1721789442bdd8e9363f4ddb90391dd3dedb67dc2c23747c526ff33bd8c5b4fb6cf6d8078f2fed81ea023ae100090eb56722eb5eb0ec899e92bc0b2ffbb5b04d6b9d7f1c813f2afbc76c02126e52cb2513fcae58aaf8cbf23ab93ce8dd43a63875ff1eff39caa1629c06370c797e443301e4c240ca1b3fb060e3606f559ccaba52fa238589145ec540b050183d19e8945139ddb998a94e3a21ca005c26ae4952b2d0d3e4b3788e1a00110d8b30db05bc6a55a92b4af64a26512c6257d1384bba7caae3b5ee25cf508d5b64e1929c5894ebaa8a505a8e2ce81af9588df482e3a3f07699acd6ee327b73281fea5bde559da05ba759e83ad53abbdcaf7d0804b89c17eca68a30d1e82eb0485138af1cf2df09e147de64cc2e6039efeb5ac1863a937d38ff6711275a940944688bcb86f4ca02c8aee3d069b902f7b262ebccc1f8bc78cdb5606617f58428b507df1fc477ee23a65b555325fd1f1387c16249b7845cd5b9550a9c6278da1c01db3ffb"
					}
				],
				"kernels": [
					{
						"features": "Plain",
						"fee": "7000000",
						"lock_height": "0",
						"excess": "08781389569d5e37d4384104e7c34f20628ed7d534b09888d43f0d47c065eaf56a",
						"excess_sig": "66074d25a751c4743342c90ad8ead9454daa00d9b9aed29bca321036d16c4b4db31f38d525f43a0a35b6ad8ce01406e042e0882dc39c8320a955f6d72a3e13d4"
					}
				]
			}
		},
		"fluff": false
		}
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 5, true, true, true);
	```
	 */

	fn post_tx(&self, token: Token, tx: TransactionV3, fluff: bool) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::cancel_tx](struct.Owner.html#method.cancel_tx).


	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "cancel_tx",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"tx_id": null,
			"tx_slate_id": "0436430c-2b02-624c-2032-570501212b00"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 5, true, true, false);
	```
	 */
	fn cancel_tx(
		&self,
		token: Token,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::get_stored_tx](struct.Owner.html#method.get_stored_tx).

	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_stored_tx",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"tx": {
				"amount_credited": "59993000000",
				"amount_debited": "120000000000",
				"confirmation_ts": "2019-01-15T16:01:26Z",
				"confirmed": false,
				"creation_ts": "2019-01-15T16:01:26Z",
				"fee": "7000000",
				"id": 5,
				"messages": {
					"messages": [
						{
							"id": "0",
							"message": null,
							"message_sig": null,
							"public_key": "033ac2158fa0077f087de60c19d8e431753baa5b63b6e1477f05a2a6e7190d4592"
						},
						{
							"id": "1",
							"message": null,
							"message_sig": null,
							"public_key": "024f9bc78c984c78d6e916d3a00746aa30fa1172124c8dbc0cbddcb7b486719bc7"
						}
					]
				},
				"num_inputs": 2,
				"num_outputs": 1,
				"parent_key_id": "0200000000000000000000000000000000",
				"stored_tx": "0436430c-2b02-624c-2032-570501212b00.keplertx",
				"tx_slate_id": "0436430c-2b02-624c-2032-570501212b00",
				"tx_type": "TxSent",
				"kernel_excess": null,
				"kernel_lookup_min_height": null
			}
		}
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"Ok": {
				"body": {
					"inputs": [
						{
							"commit": "09016c5a3376e054e20402797e4367605e30d032eda4a8752fbe05ffd8659a7fa8",
							"features": "Coinbase"
						},
						{
							"commit": "09924c88f0fe4d11ecc655b55aa54ca372260423287cc6e70c5a6062b7bee5cf24",
							"features": "Coinbase"
						}
					],
					"kernels": [
						{
							"excess": "000000000000000000000000000000000000000000000000000000000000000000",
							"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							"features": "Plain",
							"fee": "7000000",
							"lock_height": "0"
						}
					],
					"outputs": [
						{
							"commit": "08daa3f55556f7f66ef0633bbee5ccd0b670488395faa38fcf85ad180608e2e948",
							"features": "Plain",
							"proof": "07cd4b1775d3a383661370a28b158b6af378ee586b7e5a03801e7201359f993ece12cc351c3a9dcda00790276abc509708500a6b9da951387342ac5e6728ad6f021fb14f5e3616c05d9ae8025eacdeab7e3f2f296f78efabd602188e5f06df7e42f89a46c5fc2b17dbcee762ed4c6fa5bcebfaa478279f6f17c0d6bd5403c9193b99e7228fcde547a095a2b571a698fd16cda3b0d568ff86919215361c6a3f75721d5413422d859c21938c3da43ffb902e049c17ce7c68363ffa726e0de15df546ba9c0f4744d5ff5652d4fc4ba04457d657606fc9a05234bad28a8c69118e0d0c190bda9f54a0c19b16ab84bd54805f37013e729a0a83964d37100a0836f9f4d5a9aca320606e65f99301f8a9bfd00aff3634f7cc3569360a000ba01a28a9e0f304d82c9071204884a06fad0322e0c2fa213ba68cdfb4e6752f31f6b854842a9d4ecf666a6f0fb4b298cec7b17dd1aa6e6f873e2f138512505beebe39db6db5426400e0f2700bbc877c0c1989fa258fda5996b984f510d03a8b863eea8d8ca589eadd218fc945945d16704f4b5d2e3eefc8a210e99d660a291c8a6545496bf3f98b7f156193e95eb468b729ec97c4b58d6b50495981975abbf6d8af494c971a72d306f68075d5477f255b9a028dce0935a6551c6fc2adb784dbaee8d5edcb1b4eb1a5519995948140066438c050cc790c57725e630d2f910f9f94fabd432a44b6c299442a1a7916d7147ebb7a71bc113a6f7f38f13646c2b9650ce2586cc958a8e921435116a51a6e7a27d7fb4721ec8feaafbfc64931abdd34f6f12ba1e08d1ebbe1abaf7d3967e4f781dd66b35312b3ad6e7af1a5c26c9aabe95a300c1864888ca6faa44a0396f5dca89ba60dc3bd6b35d0b2a1bd28b66a010158fe7607270210444935d7da32ebd8e24c91098c0607b70311963c1ffd782a9be91f6347912c5280"
						},
						{
							"commit": "08834fe21657d6e32dd33ce0a5dd53c7a70b25a36c37ef96a8bf3c70beb10a2ef9",
							"features": "Plain",
							"proof": "282d022ea9027d115d30745ad733cd22779a5287a821dc9701fed234da26d517fb2a06adb2de670f9d473312796184affa19161bf212f4d32613f4830aaa86940bf24a2afbc862d27107ed74ebb46365c38016125bca89e4ed3b8731efc5b41ef8de7cab090b82eed987b2ab645d411b4f95ae91e20e2714848637f1b22b5bb44c7f1801cb2a7544aa674a23f74481708d11d49d25e22d8b9fbe3d20562d64a2037849a55f7c8f548e9cd7a945c08fb2e06bbca70561a7a486df87018dd7c2e6bb578d5b3b8aad6a50c4cf675fcf74756915e37dbb62ac5d559599b86a3c14f3c9690a16eddb9cc0ace33eec8f5c3732cb355a7ec22cf6dcd2a983304abb44b911d47655f399570420971cbf7d1ae28fca1ffcbf2ca90b0f720091456de43f6719e9568ec584ef3016ad53edd46c369f445641d5393f1721789442bdd8e9363f4ddb90391dd3dedb67dc2c23747c526ff33bd8c5b4fb6cf6d8078f2fed81ea023ae100090eb56722eb5eb0ec899e92bc0b2ffbb5b04d6b9d7f1c813f2afbc76c02126e52cb2513fcae58aaf8cbf23ab93ce8dd43a63875ff1eff39caa1629c06370c797e443301e4c240ca1b3fb060e3606f559ccaba52fa238589145ec540b050183d19e8945139ddb998a94e3a21ca005c26ae4952b2d0d3e4b3788e1a00110d8b30db05bc6a55a92b4af64a26512c6257d1384bba7caae3b5ee25cf508d5b64e1929c5894ebaa8a505a8e2ce81af9588df482e3a3f07699acd6ee327b73281fea5bde559da05ba759e83ad53abbdcaf7d0804b89c17eca68a30d1e82eb0485138af1cf2df09e147de64cc2e6039efeb5ac1863a937d38ff6711275a940944688bcb86f4ca02c8aee3d069b902f7b262ebccc1f8bc78cdb5606617f58428b507df1fc477ee23a65b555325fd1f1387c16249b7845cd5b9550a9c6278da1c01db3ffb"
						}
					]
				},
				"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
			}
		}
	}
	# "#
	# , true, 5, true, true, false);
	```
	 */
	fn get_stored_tx(
		&self,
		token: Token,
		tx: &TxLogEntry,
	) -> Result<Option<TransactionV3>, ErrorKind>;

	/**
	Networked version of [Owner::verify_slate_messages](struct.Owner.html#method.verify_slate_messages).

	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "verify_slate_messages",
		"id": 1,
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"slate": {
				"amount": "6000000000",
				"fee": "8000000",
				"height": "4",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"lock_height": "4",
				"ttl_cutoff_height": null,
				"num_participants": 2,
				"participant_data": [
				{
					"id": "0",
					"message": "my message",
					"message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b1d4c1358be398f801eb90d933774b5218fa7e769b11c4c640402253353656f75",
					"part_sig": null,
					"public_blind_excess": "034b4df2f0558b73ea72a1ca5c4ab20217c66bbe0829056fca7abe76888e9349ee",
					"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				}
				],
				"tx": {
					"body": {
						"inputs": [
						{
							"commit": "08e1da9e6dc4d6e808a718b2f110a991dd775d65ce5ae408a4e1f002a4961aa9e7",
							"features": "Coinbase"
						}
						],
						"kernels": [
						{
							"excess": "000000000000000000000000000000000000000000000000000000000000000000",
							"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
							"features": "HeightLocked",
							"fee": "8000000",
							"lock_height": "4"
						}
						],
						"outputs": [
						{
							"commit": "094be57c91787fc2033d5d97fae099f1a6ddb37ea48370f1a138f09524c767fdd3",
							"features": "Plain",
							"proof": "2a42e9e902b70ce44e1fccb14de87ee0a97100bddf12c6bead1b9c5f4eb60300f29c13094fa12ffeee238fb4532b18f6b61cf51b23c1c7e1ad2e41560dc27edc0a2b9e647a0b3e4e806fced5b65e61d0f1f5197d3e2285c632d359e27b6b9206b2caffea4f67e0c7a2812e7a22c134b98cf89bd43d9f28b8bec25cce037a0ac5b1ae8f667e54e1250813a5263004486b4465ad4e641ab2b535736ea26535a11013564f08f483b7dab1c2bcc3ee38eadf2f7850eff7e3459a4bbabf9f0cf6c50d0c0a4120565cd4a2ce3e354c11721cd695760a24c70e0d5a0dfc3c5dcd51dfad6de2c237a682f36dc0b271f21bb3655e5333016aaa42c2efa1446e5f3c0a79ec417c4d30f77556951cb0f05dbfafb82d9f95951a9ea241fda2a6388f73ace036b98acce079f0e4feebccc96290a86dcc89118a901210b245f2d114cf94396e4dbb461e82aa26a0581389707957968c7cdc466213bb1cd417db207ef40c05842ab67a01a9b96eb1430ebc26e795bb491258d326d5174ad549401059e41782121e506744af8af9d8e493644a87d613600888541cbbe538c625883f3eb4aa3102c5cfcc25de8e97af8927619ce6a731b3b8462d51d993066b935b0648d2344ad72e4fd70f347fbd81041042e5ea31cc7b2e3156a920b80ecba487b950ca32ca95fae85b759c936246ecf441a9fdd95e8fee932d6782cdec686064018c857efc47fb4b2a122600d5fdd79af2486f44df7e629184e1c573bc0a9b3feb40b190ef2861a1ab45e2ac2201b9cd42e495deea247269820ed32389a2810ad6c0f9a296d2a2d9c54089fed50b7f5ecfcd33ab9954360e1d7f5598c32128cfcf2a1d8bf14616818da8a5343bfa88f0eedf392e9d4ab1ace1b60324129cd4852c2e27813a9cf71a6ae6229a4fcecc1a756b3e664c5f50af333082616815a3bec8fc0b75b8e4e767d719"
						}
						]
					},
					"offset": "d202964900000000d302964900000000d402964900000000d502964900000000",
					"payment_proof": null
				},
				"version_info": {
					"orig_version": 3,
					"version": 3,
					"block_header_version": 2
				}
			}
		}
	}
	# "#
	# ,
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"result": {
			"Ok": null
		}
	}
	# "#
	# ,true, 0 ,false, false, false);
	```
	*/
	fn verify_slate_messages(&self, token: Token, slate: VersionedSlate) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::scan](struct.Owner.html#method.scan).


	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "scan",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"start_height": 1,
			"delete_unconfirmed": false
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 1, false, false, false);
	```
	 */
	fn scan(
		&self,
		token: Token,
		start_height: Option<u64>,
		delete_unconfirmed: bool,
	) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::node_height](struct.Owner.html#method.node_height).

	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "node_height",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"header_hash": "d4b3d3c40695afd8c7760f8fc423565f7d41310b7a4e1c4a4a7950a66f16240d",
				"height": "5",
				"updated_from_node": true
			}
		}
	}
	# "#
	# , true, 5, false, false, false);
	```
	 */
	fn node_height(&self, token: Token) -> Result<NodeHeightResult, ErrorKind>;

	/**
		Initializes the secure JSON-RPC API. This function must be called and a shared key
		established before any other OwnerAPI JSON-RPC function can be called.

		The shared key will be derived using ECDH with the provided public key on the secp256k1 curve. This
		function will return its public key used in the derivation, which the caller should multiply by its
		private key to derive the shared key.

		Once the key is established, all further requests and responses are encrypted and decrypted with the
		following parameters:
		* AES-256 in GCM mode with 128-bit tags and 96 bit nonces
		* 12 byte nonce which must be included in each request/response to use on the decrypting side
		* Empty vector for additional data
		* Suffix length = AES-256 GCM mode tag length = 16 bytes
		*

		Fully-formed JSON-RPC requests (as documented) should be encrypted using these parameters, encoded
		into base64 and included with the one-time nonce in a request for the `encrypted_request_v3` method
		as follows:

		```
		# let s = r#"
		{
			 "jsonrpc": "2.0",
			 "method": "encrypted_request_v3",
			 "id": "1",
			 "params": {
					"nonce": "ef32...",
					"body_enc": "e0bcd..."
			 }
		}
		# "#;
		```

		With a typical response being:

		```
		# let s = r#"{
		{
			 "jsonrpc": "2.0",
			 "method": "encrypted_response_v3",
			 "id": "1",
			 "Ok": {
					"nonce": "340b...",
					"body_enc": "3f09c..."
			 }
		}
		# }"#;
		```

	*/

	fn init_secure_api(&self, ecdh_pubkey: ECDHPubkey) -> Result<ECDHPubkey, ErrorKind>;

	/**
	Networked version of [Owner::get_top_level_directory](struct.Owner.html#method.get_top_level_directory).

	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_top_level_directory",
		"params": {
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": "/doctest/dir"
		}
	}
	# "#
	# , true, 5, false, false, false);
	```
	*/

	fn get_top_level_directory(&self) -> Result<String, ErrorKind>;

	/**
	Networked version of [Owner::set_top_level_directory](struct.Owner.html#method.set_top_level_directory).
	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "set_top_level_directory",
		"params": {
			"dir": "/home/wallet_user/my_wallet_dir"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 5, false, false, false);
	```
	*/

	fn set_top_level_directory(&self, dir: String) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::create_config](struct.Owner.html#method.create_config).

	Both the `wallet_config` and `logging_config` parameters can be `null`, the examples
	below are for illustration. Note that the values provided for `log_file_path` and `data_file_dir`
	will be ignored and replaced with the actual values based on the value of `get_top_level_directory`
	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "create_config",
		"params": {
			"chain_type": "Mainnet",
			"wallet_config": {
				"chain_type": null,
				"api_listen_interface": "127.0.0.1",
				"api_listen_port": 3415,
				"owner_api_listen_port": 3420,
				"api_secret_path": null,
				"node_api_secret_path": null,
				"check_node_api_http_addr": "http://127.0.0.1:3413",
				"owner_api_include_foreign": false,
				"data_file_dir": "/path/to/data/file/dir",
				"no_commit_cache": null,
				"tls_certificate_file": null,
				"tls_certificate_key": null,
				"dark_background_color_scheme": null,
				"keybase_notify_ttl": null
			},
			"logging_config": {
				"log_to_stdout": false,
				"stdout_log_level": "Info",
				"log_to_file": true,
				"file_log_level": "Debug",
				"log_file_path": "/path/to/log/file",
				"log_file_append": true,
				"log_max_size": null,
				"log_max_files": null,
				"tui_running": null
			},
			"tor_config" : {
				"use_tor_listener": true,
				"socks_proxy_addr": "127.0.0.1:9050",
				"send_config_dir": "."
			}
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 5, false, false, false);
	```
	*/
	fn create_config(
		&self,
		chain_type: global::ChainTypes,
		wallet_config: Option<WalletConfig>,
		logging_config: Option<LoggingConfig>,
		tor_config: Option<TorConfig>,
	) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::create_wallet](struct.Owner.html#method.create_wallet).
	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "create_wallet",
		"params": {
			"name": null,
			"mnemonic": null,
			"mnemonic_length": 0,
			"password": "my_secret_password"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 0, false, false, false);
	```
	*/

	fn create_wallet(
		&self,
		name: Option<String>,
		mnemonic: Option<String>,
		mnemonic_length: u32,
		password: String,
	) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::open_wallet](struct.Owner.html#method.open_wallet).
	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "open_wallet",
		"params": {
			"name": null,
			"password": "my_secret_password"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": "d096b3cb75986b3b13f80b8f5243a9edf0af4c74ac37578c5a12cfb5b59b1868"
		}
	}
	# "#
	# , true, 0, false, false, false);
	```
	*/

	fn open_wallet(&self, name: Option<String>, password: String) -> Result<Token, ErrorKind>;

	/**
	Networked version of [Owner::close_wallet](struct.Owner.html#method.close_wallet).
	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "close_wallet",
		"params": {
			"name": null
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 0, false, false, false);
	```
	*/

	fn close_wallet(&self, name: Option<String>) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::get_mnemonic](struct.Owner.html#method.get_mnemonic).
	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_mnemonic",
		"params": {
			"name": null,
			"password": ""
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": "fat twenty mean degree forget shell check candy immense awful flame next during february bulb bike sun wink theory day kiwi embrace peace lunch"
		}
	}
	# "#
	# , true, 0, false, false, false);
	```
	*/

	fn get_mnemonic(&self, name: Option<String>, password: String) -> Result<String, ErrorKind>;

	/**
	Networked version of [Owner::change_password](struct.Owner.html#method.change_password).
	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "change_password",
		"params": {
			"name": null,
			"old": "",
			"new": "new_password"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 0, false, false, false);
	```
	*/
	fn change_password(
		&self,
		name: Option<String>,
		old: String,
		new: String,
	) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::delete_wallet](struct.Owner.html#method.delete_wallet).
	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "delete_wallet",
		"params": {
			"name": null
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 0, false, false, false);
	```
	*/
	fn delete_wallet(&self, name: Option<String>) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::start_updated](struct.Owner.html#method.start_updater).
	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "start_updater",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"frequency": 30000
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 0, false, false, false);
	```
	*/

	fn start_updater(&self, token: Token, frequency: u32) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::stop_updater](struct.Owner.html#method.stop_updater).
	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "stop_updater",
		"params": null,
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 0, false, false, false);
	```
	*/
	fn stop_updater(&self) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::get_updater_messages](struct.Owner.html#method.get_updater_messages).
	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_updater_messages",
		"params": {
			"count": 1
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": []
		}
	}
	# "#
	# , true, 0, false, false, false);
	```
	*/

	fn get_updater_messages(&self, count: u32) -> Result<Vec<StatusMessage>, ErrorKind>;

	/**
	Networked version of [Owner::get_public_proof_address](struct.Owner.html#method.get_public_proof_address).
	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_public_proof_address",
		"params": {
			"token": "d202964900000000d302964900000000d402964900000000d502964900000000",
			"derivation_index": 0
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": "32cdd63928854f8b2628b1dce4626ddcdf35d56cb7cfdf7d64cca5822b78d4d3"
		}
	}
	# "#
	# , true, 0, false, false, false);
	```
	*/

	fn get_public_proof_address(
		&self,
		token: Token,
		derivation_index: u32,
	) -> Result<PubAddress, ErrorKind>;

	/**
	Networked version of [Owner::proof_address_from_onion_v3](struct.Owner.html#method.proof_address_from_onion_v3).
	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "proof_address_from_onion_v3",
		"params": {
			"address_v3": "2a6at2obto3uvkpkitqp4wxcg6u36qf534eucbskqciturczzc5suyid"
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": "d03c09e9c19bb74aa9ea44e0fe5ae237a9bf40bddf0941064a80913a4459c8bb"
		}
	}
	# "#
	# , true, 0, false, false, false);
	```
	*/

	fn proof_address_from_onion_v3(&self, address_v3: String) -> Result<PubAddress, ErrorKind>;

	/**
	Networked version of [Owner::set_tor_config](struct.Owner.html#method.set_tor_config).
	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "set_tor_config",
		"params": {
			"tor_config": {
				"use_tor_listener": true,
				"socks_proxy_addr": "127.0.0.1:59050",
				"send_config_dir": "."
			}
		},
		"id": 1
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": null
		}
	}
	# "#
	# , true, 0, false, false, false);
	```
	*/
	fn set_tor_config(&self, tor_config: Option<TorConfig>) -> Result<(), ErrorKind>;
}

impl<L, C, K> OwnerRpcS for Owner<L, C, K>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn accounts(&self, token: Token) -> Result<Vec<AcctPathMapping>, ErrorKind> {
		Owner::accounts(self, (&token.keychain_mask).as_ref()).map_err(|e| e.kind())
	}

	fn create_account_path(&self, token: Token, label: &String) -> Result<Identifier, ErrorKind> {
		Owner::create_account_path(self, (&token.keychain_mask).as_ref(), label)
			.map_err(|e| e.kind())
	}

	fn set_active_account(&self, token: Token, label: &String) -> Result<(), ErrorKind> {
		Owner::set_active_account(self, (&token.keychain_mask).as_ref(), label)
			.map_err(|e| e.kind())
	}

	fn retrieve_outputs(
		&self,
		token: Token,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), ErrorKind> {
		Owner::retrieve_outputs(
			self,
			(&token.keychain_mask).as_ref(),
			include_spent,
			refresh_from_node,
			tx_id,
		)
		.map_err(|e| e.kind())
	}

	fn retrieve_txs(
		&self,
		token: Token,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), ErrorKind> {
		Owner::retrieve_txs(
			self,
			(&token.keychain_mask).as_ref(),
			refresh_from_node,
			tx_id,
			tx_slate_id,
		)
		.map_err(|e| e.kind())
	}

	fn retrieve_summary_info(
		&self,
		token: Token,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), ErrorKind> {
		Owner::retrieve_summary_info(
			self,
			(&token.keychain_mask).as_ref(),
			refresh_from_node,
			minimum_confirmations,
		)
		.map_err(|e| e.kind())
	}

	fn init_send_tx(&self, token: Token, args: InitTxArgs) -> Result<VersionedSlate, ErrorKind> {
		let slate = Owner::init_send_tx(self, (&token.keychain_mask).as_ref(), args)
			.map_err(|e| e.kind())?;
		let version = SlateVersion::V3;
		Ok(VersionedSlate::into_version(slate, version))
	}

	fn issue_invoice_tx(
		&self,
		token: Token,
		args: IssueInvoiceTxArgs,
	) -> Result<VersionedSlate, ErrorKind> {
		let slate = Owner::issue_invoice_tx(self, (&token.keychain_mask).as_ref(), args)
			.map_err(|e| e.kind())?;
		let version = SlateVersion::V3;
		Ok(VersionedSlate::into_version(slate, version))
	}

	fn process_invoice_tx(
		&self,
		token: Token,
		in_slate: VersionedSlate,
		args: InitTxArgs,
	) -> Result<VersionedSlate, ErrorKind> {
		let out_slate = Owner::process_invoice_tx(
			self,
			(&token.keychain_mask).as_ref(),
			&Slate::from(in_slate),
			args,
		)
		.map_err(|e| e.kind())?;
		let version = SlateVersion::V3;
		Ok(VersionedSlate::into_version(out_slate, version))
	}

	fn finalize_tx(
		&self,
		token: Token,
		in_slate: VersionedSlate,
	) -> Result<VersionedSlate, ErrorKind> {
		let out_slate = Owner::finalize_tx(
			self,
			(&token.keychain_mask).as_ref(),
			&Slate::from(in_slate),
		)
		.map_err(|e| e.kind())?;
		let version = SlateVersion::V3;
		Ok(VersionedSlate::into_version(out_slate, version))
	}

	fn tx_lock_outputs(
		&self,
		token: Token,
		in_slate: VersionedSlate,
		participant_id: usize,
	) -> Result<(), ErrorKind> {
		Owner::tx_lock_outputs(
			self,
			(&token.keychain_mask).as_ref(),
			&Slate::from(in_slate),
			participant_id,
		)
		.map_err(|e| e.kind())
	}

	fn cancel_tx(
		&self,
		token: Token,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(), ErrorKind> {
		Owner::cancel_tx(self, (&token.keychain_mask).as_ref(), tx_id, tx_slate_id)
			.map_err(|e| e.kind())
	}

	fn get_stored_tx(
		&self,
		token: Token,
		tx: &TxLogEntry,
	) -> Result<Option<TransactionV3>, ErrorKind> {
		Owner::get_stored_tx(self, (&token.keychain_mask).as_ref(), tx)
			.map(|x| x.map(|y| TransactionV3::from(y)))
			.map_err(|e| e.kind())
	}

	fn post_tx(&self, token: Token, tx: TransactionV3, fluff: bool) -> Result<(), ErrorKind> {
		Owner::post_tx(
			self,
			(&token.keychain_mask).as_ref(),
			&Transaction::from(tx),
			fluff,
		)
		.map_err(|e| e.kind())
	}

	fn verify_slate_messages(&self, token: Token, slate: VersionedSlate) -> Result<(), ErrorKind> {
		Owner::verify_slate_messages(self, (&token.keychain_mask).as_ref(), &Slate::from(slate))
			.map_err(|e| e.kind())
	}

	fn scan(
		&self,
		token: Token,
		start_height: Option<u64>,
		delete_unconfirmed: bool,
	) -> Result<(), ErrorKind> {
		Owner::scan(
			self,
			(&token.keychain_mask).as_ref(),
			start_height,
			delete_unconfirmed,
		)
		.map_err(|e| e.kind())
	}

	fn node_height(&self, token: Token) -> Result<NodeHeightResult, ErrorKind> {
		Owner::node_height(self, (&token.keychain_mask).as_ref()).map_err(|e| e.kind())
	}

	fn init_secure_api(&self, ecdh_pubkey: ECDHPubkey) -> Result<ECDHPubkey, ErrorKind> {
		let secp_inst = static_secp_instance();
		let secp = secp_inst.lock();
		let sec_key = SecretKey::new(&secp, &mut thread_rng());

		let mut shared_pubkey = ecdh_pubkey.ecdh_pubkey.clone();
		shared_pubkey
			.mul_assign(&secp, &sec_key)
			.map_err(|e| ErrorKind::Secp(e))?;

		let x_coord = shared_pubkey.serialize_vec(&secp, true);
		let shared_key =
			SecretKey::from_slice(&secp, &x_coord[1..]).map_err(|e| ErrorKind::Secp(e))?;
		{
			let mut s = self.shared_key.lock();
			*s = Some(shared_key);
		}

		let pub_key =
			PublicKey::from_secret_key(&secp, &sec_key).map_err(|e| ErrorKind::Secp(e))?;

		Ok(ECDHPubkey {
			ecdh_pubkey: pub_key,
		})
	}

	fn get_top_level_directory(&self) -> Result<String, ErrorKind> {
		Owner::get_top_level_directory(self).map_err(|e| e.kind())
	}

	fn set_top_level_directory(&self, dir: String) -> Result<(), ErrorKind> {
		Owner::set_top_level_directory(self, &dir).map_err(|e| e.kind())
	}

	fn create_config(
		&self,
		chain_type: global::ChainTypes,
		wallet_config: Option<WalletConfig>,
		logging_config: Option<LoggingConfig>,
		tor_config: Option<TorConfig>,
	) -> Result<(), ErrorKind> {
		Owner::create_config(self, &chain_type, wallet_config, logging_config, tor_config)
			.map_err(|e| e.kind())
	}

	fn create_wallet(
		&self,
		name: Option<String>,
		mnemonic: Option<String>,
		mnemonic_length: u32,
		password: String,
	) -> Result<(), ErrorKind> {
		let n = name.as_ref().map(|s| s.as_str());
		let m = match mnemonic {
			Some(s) => Some(ZeroingString::from(s)),
			None => None,
		};
		Owner::create_wallet(self, n, m, mnemonic_length, ZeroingString::from(password))
			.map_err(|e| e.kind())
	}

	fn open_wallet(&self, name: Option<String>, password: String) -> Result<Token, ErrorKind> {
		let n = name.as_ref().map(|s| s.as_str());
		let sec_key = Owner::open_wallet(self, n, ZeroingString::from(password), true)
			.map_err(|e| e.kind())?;
		Ok(Token {
			keychain_mask: sec_key,
		})
	}

	fn close_wallet(&self, name: Option<String>) -> Result<(), ErrorKind> {
		let n = name.as_ref().map(|s| s.as_str());
		Owner::close_wallet(self, n).map_err(|e| e.kind())
	}

	fn get_mnemonic(&self, name: Option<String>, password: String) -> Result<String, ErrorKind> {
		let n = name.as_ref().map(|s| s.as_str());
		let res =
			Owner::get_mnemonic(self, n, ZeroingString::from(password)).map_err(|e| e.kind())?;
		Ok(format!("{}", &*res))
	}

	fn change_password(
		&self,
		name: Option<String>,
		old: String,
		new: String,
	) -> Result<(), ErrorKind> {
		let n = name.as_ref().map(|s| s.as_str());
		Owner::change_password(self, n, ZeroingString::from(old), ZeroingString::from(new))
			.map_err(|e| e.kind())
	}

	fn delete_wallet(&self, name: Option<String>) -> Result<(), ErrorKind> {
		let n = name.as_ref().map(|s| s.as_str());
		Owner::delete_wallet(self, n).map_err(|e| e.kind())
	}

	fn start_updater(&self, token: Token, frequency: u32) -> Result<(), ErrorKind> {
		Owner::start_updater(
			self,
			(&token.keychain_mask).as_ref(),
			Duration::from_millis(frequency as u64),
		)
		.map_err(|e| e.kind())
	}

	fn stop_updater(&self) -> Result<(), ErrorKind> {
		Owner::stop_updater(self).map_err(|e| e.kind())
	}

	fn get_updater_messages(&self, count: u32) -> Result<Vec<StatusMessage>, ErrorKind> {
		Owner::get_updater_messages(self, count as usize).map_err(|e| e.kind())
	}

	fn get_public_proof_address(
		&self,
		token: Token,
		derivation_index: u32,
	) -> Result<PubAddress, ErrorKind> {
		let address = Owner::get_public_proof_address(
			self,
			(&token.keychain_mask).as_ref(),
			derivation_index,
		)
		.map_err(|e| e.kind())?;
		Ok(PubAddress { address })
	}

	fn proof_address_from_onion_v3(&self, address_v3: String) -> Result<PubAddress, ErrorKind> {
		let address =
			Owner::proof_address_from_onion_v3(self, &address_v3).map_err(|e| e.kind())?;
		Ok(PubAddress { address })
	}

	fn set_tor_config(&self, tor_config: Option<TorConfig>) -> Result<(), ErrorKind> {
		Owner::set_tor_config(self, tor_config);
		Ok(())
	}
}
