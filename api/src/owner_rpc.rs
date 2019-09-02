// Copyright 2019 The Kepler Developers
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

use crate::core::core::Transaction;
use crate::keychain::{Identifier, Keychain};
use crate::libwallet::slate_versions::v2::TransactionV2;
use crate::libwallet::{
	AcctPathMapping, ErrorKind, InitTxArgs, IssueInvoiceTxArgs, NodeClient, NodeHeightResult,
	OutputCommitMapping, Slate, SlateVersion, TxLogEntry, VersionedSlate, WalletInfo,
	WalletLCProvider,
};
use crate::util::Mutex;
use crate::{Owner, OwnerRpcS};
use easy_jsonrpc_mw;
use std::sync::Arc;

/// Public definition used to generate Owner jsonrpc api.
/// * When running `kepler-wallet owner_api` with defaults, the V2 api is available at
/// `localhost:7420/v2/owner`
/// * The endpoint only supports POST operations, with the json-rpc request as the body
#[easy_jsonrpc_mw::rpc]
pub trait OwnerRpc: Sync + Send {
	/**
	Networked version of [Owner::accounts](struct.Owner.html#method.accounts).

	# Json rpc example

	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "accounts",
		"params": [],
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
	# , false, 4, false, false, false);
	```
	*/
	fn accounts(&self) -> Result<Vec<AcctPathMapping>, ErrorKind>;

	/**
	Networked version of [Owner::create_account_path](struct.Owner.html#method.create_account_path).

	# Json rpc example

	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "create_account_path",
		"params": ["account1"],
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
	# ,false, 4, false, false, false);
	```
	 */
	fn create_account_path(&self, label: &String) -> Result<Identifier, ErrorKind>;

	/**
	Networked version of [Owner::set_active_account](struct.Owner.html#method.set_active_account).

	# Json rpc example

	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "set_active_account",
		"params": ["default"],
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
	# , false, 4, false, false, false);
	```
	 */
	fn set_active_account(&self, label: &String) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::retrieve_outputs](struct.Owner.html#method.retrieve_outputs).

	# Json rpc example

	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "retrieve_outputs",
		"params": [false, true, null],
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
	# , false, 2, false, false, false);
	```
	*/
	fn retrieve_outputs(
		&self,
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
			"params": [true, null, null],
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
			  "messages": null,
			  "num_inputs": 0,
			  "num_outputs": 1,
			  "parent_key_id": "0200000000000000000000000000000000",
			  "stored_tx": null,
			  "tx_slate_id": null,
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
			  "messages": null,
			  "num_inputs": 0,
			  "num_outputs": 1,
			  "parent_key_id": "0200000000000000000000000000000000",
			  "stored_tx": null,
			  "tx_slate_id": null,
			  "tx_type": "ConfirmedCoinbase"
			}
		  ]
		]
	  }
	}
	# "#
	# , false, 2, false, false, false);
	```
	*/

	fn retrieve_txs(
		&self,
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
		"params": [true, 1],
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
	# ,false, 4, false, false, false);
	```
	 */

	fn retrieve_summary_info(
		&self,
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
				"args": {
					"src_acct_name": null,
					"amount": "100000000000",
					"minimum_confirmations": 2,
					"max_outputs": 500,
					"num_change_outputs": 1,
					"selection_strategy_is_use_all": true,
					"message": "my message",
					"target_slate_version": null,
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
		  "amount": "100000000000",
		  "fee": "8000000",
		  "height": "4",
		  "id": "0436430c-2b02-624c-2032-570501212b00",
		  "lock_height": "0",
		  "num_participants": 2,
		  "participant_data": [
			{
			  "id": "0",
			  "message": "my message",
			  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b691cf3d54f980573a705782a74df2123f98547b49c40a013b5b69c7bca71aeee",
			  "part_sig": null,
			  "public_blind_excess": "027da3bc74bdfa9d57bc068ba0fbc3157cb8d03428806a75f7f28293cb1920e074",
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
				  "commit": "097465837a7152837e0b12ed57b3cb9cfd65a3b1ece8d37333c3bd75ba80262012",
				  "features": "Plain",
				  "proof": "2209203deba0a66e16e726ff52ab630683ee8a5a80b9fa78573a6684a1264808c435e5e2c5307558655ed44a4881c00a5e5967ffdf3d42865ec3cf776ce0a96008fdaa84cc34496848714fe445c9b5f154c93baabf323ca6b6dfe4aa157b9eee7c0aa565a7364dcd03155e6c787de2a70d25d6d6382d5293e9f5bd5dc5b17266e3dfad50194d5e0f71fd92a57e964e3a4e53eda46ac6121e5057a5516a80fa9b460a3e0d8e34dd58c3e2d5b33ec5c34a18c1d7d27cfad2d111899621be9fdac31e5899fac91a5028a946b73240f64390dd4ff86ba58c5b81f07d82441ca01f2f3739ce83db69fa2bb1c416060795b2c3e87bcc48dc95386c990b236ba4e26ab01d8b08cc9f43b097c8f86e46727e2a215af0235203aa0ed1ba78321e25e758b045bb9a3561f13b903aaac9d1794f4e003e0984fb43879f237cd8ea22263cc28efeda60f7fd03c19b5961429a8dfa88cf662590fb8cabb2a3d679f8375c93da1a3853031780ddd14eca5b33d6dd921492d468b1822f68bd831f26e0eb1c03440662818418f44423264d38565083107942a9481ddfae04d364eddc64d30e817fe54f41a592e65d852c3fa019eb9151726f9180c81d4ce349d78ea17c84e061854c51388d167cdf5f0845d529ef37922b33e28356fcdcd94d699a965411f107aaee95d1560e783b9aca2f9c4a897e777e4edcbc426c5252494a0a32a15d63807c068800e85b1ed9f51e1326dd06e751ed18aaa0b3618096e3f5664a43e125f1a27d7aaf456ea689755468393eb56cf4a2b4a04be738825c1d31e5baee405c0e2943fccdb1e9f1ac9a6d9964606d49e12d198d291334bc4acd3bdf65adabc35167825f0c1da5a6781e367a927215ccf5f378f6832b7af91b23161c6e07fb2471c54f5e49cb8b22fb51a237fe0866bf08e85df2624df2fbf567e5f32375b1f409b000417b00"
				}
			  ]
			},
			"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
		  },
		  "version_info": {
				"orig_version": 2,
				"version": 2,
				"block_header_version": 1
		  }
		}
	  }
	}
		# "#
		# ,false, 4, false, false, false);
	```
	*/

	fn init_send_tx(&self, args: InitTxArgs) -> Result<VersionedSlate, ErrorKind>;

	/**
		Networked version of [Owner::issue_invoice_tx](struct.Owner.html#method.issue_invoice_tx).

	```
		# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "issue_invoice_tx",
			"params": {
				"args": {
					"amount": "100000000000",
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
					"amount": "100000000000",
					"fee": "0",
					"height": "4",
					"id": "0436430c-2b02-624c-2032-570501212b00",
					"lock_height": "0",
					"num_participants": 2,
					"participant_data": [
						{
							"id": "1",
							"message": "Please give me your keplers",
							"message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841ba16507a56ad4b85240db06ffcef2001fe6afdf547aa9adebe8b543369a6346f8",
							"part_sig": null,
							"public_blind_excess": "02e644caf501dbf58c8c25d1ead1b87c81300303f8da397fcb8cd45187cba9854e",
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
									"commit": "09a7ed8bd0a1098c2a8a8719cfd2bf8f41b43fadeb19999cf774b716d70b2cb53b",
									"features": "Plain",
									"proof": "a7bf35b9be218b239c444cf06a7c2e3355d4f777cf45bdfade57b99274e9c52fad93db99300631085f6526ec7f55064c2091d12540606e83336470f6dacaf1ab04dacfadab8307d1b40d2c71bebb3ae2ea9d83c57e7fd7a1a401ff4c18e6d181f63cb9a58fd3455e3d1a1c8fff66adfd1fdab39e81b57f7da7cabdd7663a37e47186e06a6eacb3453058b5666732f9f5a2b182c85878e53de6ecbad1fd3a837283ff455b866eaf601e51497aa10503127638688e277a99adc1414fdb5adc4331c37be89197d8fe2029ce655e92c51b02fbd307590c91713cb6fbc0a0931561d23d189b223c44f1998b37ac729a8f9b1043319f5bcbfca859acb9047841d9b2988b725d5416bbf89287797f4f5e77895d400a98094353e4cf0bd6356605d822acb82e9bf56d46dba1433e0db151567f97da50205087f4770009003019906446353ac78b63f3012ed76c85eedcbc177b00519b72a168ca51100e0ef2f430357353d6cb0073e964d945ec078cb54ba2913888b0f93ebc796714f31141b6a3fc95d8f500bca26759e06721c3df13d5bd8d8edf5671b80c6027486e5a3c715934948f7efdc471c338d113aef3423da34cdb34bdf76625e872375cc52c55cce9cb888e2d748883bdb53a83b1844971ed5e5ce16e7fe3f622d5c9627b4ffc934ed60f1f71133785a65bf1431b596ac5eed679063d34d6b0cf92b1a8c4b681c7c1157cefbdb84aa6fa4f1dfeaa5200261b5d6545e3cca3430bd2034b3459ce7d1d76f05cc7b1ac017e3bbda6a6495f45ac705d5eb24cec3018e46722751bfda72e64af476cf7240604a9e1bbaee64f5631446cf68c078c8fad6b3a92b5684574161b0da00c20a11d1fd051ffab6d3203c555505804a41733b24dd57521055b8457f5a4172b67a75de5449826e7c79390bc4c4e89af70490ef5e71f7f277e43ef919cf555ee6afe"
								}
							]
						},
						"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
					},
					"version_info": {
						"orig_version": 2,
						"version": 2,
						"block_header_version": 1
					}
				}
			}
		}
		# "#
		# ,false, 4, false, false, false);
	```
	*/

	fn issue_invoice_tx(&self, args: IssueInvoiceTxArgs) -> Result<VersionedSlate, ErrorKind>;

	/**
		 Networked version of [Owner::process_invoice_tx](struct.Owner.html#method.process_invoice_tx).

	```
		# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
		# r#"
		{
			"jsonrpc": "2.0",
			"method": "process_invoice_tx",
			"params": [
				{
					"amount": "100000000000",
					"fee": "0",
					"height": "4",
					"id": "0436430c-2b02-624c-2032-570501212b00",
					"lock_height": "0",
					"num_participants": 2,
					"participant_data": [
						{
							"id": "1",
							"message": "Please give me your keplers",
							"message_sig": "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078ff846639a3643b5e8ebada97a54dfafe61f00f2ceff06db4052b8d46aa50765a1",
							"part_sig": null,
							"public_blind_excess": "02e644caf501dbf58c8c25d1ead1b87c81300303f8da397fcb8cd45187cba9854e",
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
									"commit": "09a7ed8bd0a1098c2a8a8719cfd2bf8f41b43fadeb19999cf774b716d70b2cb53b",
									"features": "Plain",
									"proof": "1e1daa21c86de6e941e31a9478e047e11fe6ff79c075aba7c4de4fd7217bf80755fe4b0c1a92bf77656a07b83df52247a6a1b622d135da1dadcd3df65d84dfd20b6ebfcebce0f2aec09d2c8e6ccde1f31d77a53c1e90ddab5b64e38f1cd068e1ff921a8181b7d1ebd0622cd014fdb7cab7d2233a378de335ed1b78dd461d0cca09eb86c1529d363c890a023e3b55fa813e0cc10b7c9c51afef5cd709edd4f0b31826432c1e5928f5916029242addf996843c3a9ef76f4b020f84aa04b8044ad53590540b04c34e4fb35c70dbaa81090e5be794b8a83546657529dbd1e07ca35742cb5d3fbbe9e341ae85500017e9c373f0502e8e09871f04c29dc67d0e2e6836d3a8b3a91d1240591a0beb4db2532db8d6afde33d2ee80a3ee9a68ebeee2f024446dda34f909dbbd7a1f2ca7d88beb14e6912df8dec1122c81fa7289cbb0e82a209f8b2596fe598dd6d1a13b5d0bfaca853679bdd61b1c42c0c8935b3cb2f7a602ce0052150daaaa89bb41d54e39e21fb533fe06bc02d63b4b65cb1aa165bf0fe4a92823b184caf80a18df137a244ecd45eb8352ebde6868721b3742701c1cb81d76a759cde6ec3cc177ba1b98a6ed10c72605dd2d7c173ae780b9d1d1b95ef9d7e9b0036fcf0efaee7d2d4c730d72127a7bc94451db2b682a3cbed1ec439f45dbcb726f6b345e12796c32f42221338fab40b63e5f6850033ef7123e403b9816ab9b079d0e30d9838bb3b15ed98839a55c5b0310e5aee18b901e8827dd9e415ea6e00b490550b114eeb76be5c56259a205be2ef50ce1bbe8e810673931d4c74265a3ef6e35e2db458b1f68c82ba181f7f6b1b485a7a88e5f174feba3c42e6e650dd37043576565e517b3cbce4734022adc96343cc04d522b6a1f18f8e805624a49bc8ece332bc773dc13d67f3bbe4820a9e725960213b28a98f208439e362af7ecd1ea"
								}
							]
						},
						"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
					},
					"version_info": {
						"orig_version": 2,
						"version": 2,
						"block_header_version": 2
					}
				},
				{
					"src_acct_name": null,
					"amount": "0",
					"minimum_confirmations": 2,
					"max_outputs": 500,
					"num_change_outputs": 1,
					"selection_strategy_is_use_all": true,
					"message": "Ok, here are your keplers",
					"target_slate_version": null,
					"send_args": null
				}
			],
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
				"amount": "100000000000",
				"fee": "8000000",
				"height": "4",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"lock_height": "0",
				"num_participants": 2,
				"participant_data": [
					{
						"id": "1",
						"message": "Please give me your keplers",
						"message_sig": "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078ff846639a3643b5e8ebada97a54dfafe61f00f2ceff06db4052b8d46aa50765a1",
						"part_sig": null,
						"public_blind_excess": "02e644caf501dbf58c8c25d1ead1b87c81300303f8da397fcb8cd45187cba9854e",
						"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					},
					{
						"id": "0",
						"message": "Ok, here are your keplers",
						"message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841baddf1f800697e5743935ddbd0c9e9e5fcd37d00a72db14210e7c55417d730a4b",
						"part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bd2c5d079888206c5cc78688a3d6952e9f0da43a1e5e8099ad02ffd6bc8a99dcc",
						"public_blind_excess": "020ef0385ffbb4a8506886bd0aad778922acfaae406d765813757b7a08e4045657",
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
								"commit": "09a7ed8bd0a1098c2a8a8719cfd2bf8f41b43fadeb19999cf774b716d70b2cb53b",
								"features": "Plain",
								"proof": "1e1daa21c86de6e941e31a9478e047e11fe6ff79c075aba7c4de4fd7217bf80755fe4b0c1a92bf77656a07b83df52247a6a1b622d135da1dadcd3df65d84dfd20b6ebfcebce0f2aec09d2c8e6ccde1f31d77a53c1e90ddab5b64e38f1cd068e1ff921a8181b7d1ebd0622cd014fdb7cab7d2233a378de335ed1b78dd461d0cca09eb86c1529d363c890a023e3b55fa813e0cc10b7c9c51afef5cd709edd4f0b31826432c1e5928f5916029242addf996843c3a9ef76f4b020f84aa04b8044ad53590540b04c34e4fb35c70dbaa81090e5be794b8a83546657529dbd1e07ca35742cb5d3fbbe9e341ae85500017e9c373f0502e8e09871f04c29dc67d0e2e6836d3a8b3a91d1240591a0beb4db2532db8d6afde33d2ee80a3ee9a68ebeee2f024446dda34f909dbbd7a1f2ca7d88beb14e6912df8dec1122c81fa7289cbb0e82a209f8b2596fe598dd6d1a13b5d0bfaca853679bdd61b1c42c0c8935b3cb2f7a602ce0052150daaaa89bb41d54e39e21fb533fe06bc02d63b4b65cb1aa165bf0fe4a92823b184caf80a18df137a244ecd45eb8352ebde6868721b3742701c1cb81d76a759cde6ec3cc177ba1b98a6ed10c72605dd2d7c173ae780b9d1d1b95ef9d7e9b0036fcf0efaee7d2d4c730d72127a7bc94451db2b682a3cbed1ec439f45dbcb726f6b345e12796c32f42221338fab40b63e5f6850033ef7123e403b9816ab9b079d0e30d9838bb3b15ed98839a55c5b0310e5aee18b901e8827dd9e415ea6e00b490550b114eeb76be5c56259a205be2ef50ce1bbe8e810673931d4c74265a3ef6e35e2db458b1f68c82ba181f7f6b1b485a7a88e5f174feba3c42e6e650dd37043576565e517b3cbce4734022adc96343cc04d522b6a1f18f8e805624a49bc8ece332bc773dc13d67f3bbe4820a9e725960213b28a98f208439e362af7ecd1ea"
							},
							{
								"commit": "097465837a7152837e0b12ed57b3cb9cfd65a3b1ece8d37333c3bd75ba80262012",
								"features": "Plain",
								"proof": "2209203deba0a66e16e726ff52ab630683ee8a5a80b9fa78573a6684a1264808c435e5e2c5307558655ed44a4881c00a5e5967ffdf3d42865ec3cf776ce0a96008fdaa84cc34496848714fe445c9b5f154c93baabf323ca6b6dfe4aa157b9eee7c0aa565a7364dcd03155e6c787de2a70d25d6d6382d5293e9f5bd5dc5b17266e3dfad50194d5e0f71fd92a57e964e3a4e53eda46ac6121e5057a5516a80fa9b460a3e0d8e34dd58c3e2d5b33ec5c34a18c1d7d27cfad2d111899621be9fdac31e5899fac91a5028a946b73240f64390dd4ff86ba58c5b81f07d82441ca01f2f3739ce83db69fa2bb1c416060795b2c3e87bcc48dc95386c990b236ba4e26ab01d8b08cc9f43b097c8f86e46727e2a215af0235203aa0ed1ba78321e25e758b045bb9a3561f13b903aaac9d1794f4e003e0984fb43879f237cd8ea22263cc28efeda60f7fd03c19b5961429a8dfa88cf662590fb8cabb2a3d679f8375c93da1a3853031780ddd14eca5b33d6dd921492d468b1822f68bd831f26e0eb1c03440662818418f44423264d38565083107942a9481ddfae04d364eddc64d30e817fe54f41a592e65d852c3fa019eb9151726f9180c81d4ce349d78ea17c84e061854c51388d167cdf5f0845d529ef37922b33e28356fcdcd94d699a965411f107aaee95d1560e783b9aca2f9c4a897e777e4edcbc426c5252494a0a32a15d63807c068800e85b1ed9f51e1326dd06e751ed18aaa0b3618096e3f5664a43e125f1a27d7aaf456ea689755468393eb56cf4a2b4a04be738825c1d31e5baee405c0e2943fccdb1e9f1ac9a6d9964606d49e12d198d291334bc4acd3bdf65adabc35167825f0c1da5a6781e367a927215ccf5f378f6832b7af91b23161c6e07fb2471c54f5e49cb8b22fb51a237fe0866bf08e85df2624df2fbf567e5f32375b1f409b000417b00"
							}
						]
					},
					"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
				},
				"version_info": {
					"orig_version": 2,
					"version": 2,
					"block_header_version": 2
				}
			}
		}
	}
	# "#
	# ,false, 4, false, false, false);
	```
	*/

	fn process_invoice_tx(
		&self,
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
		"params": [ {
				"amount": "6000000000",
				"fee": "8000000",
				"height": "4",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"lock_height": "4",
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
					"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
				},
				"version_info": {
					"orig_version": 2,
					"version": 2,
					"block_header_version": 2
				}
			},
			0
		]
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
	# ,false, 5 ,true, false, false);

	```
	 */
	fn tx_lock_outputs(
		&self,
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
		"params": [
		{
			"version_info": {
				"version": 2,
				"orig_version": 2,
				"block_header_version": 2
			},
			"num_participants": 2,
			"id": "0436430c-2b02-624c-2032-570501212b00",
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
							"proof": "d24a6aa4f74ee607ef163713e2cfea0b435463ddf46392f6615c09519c8d76617cd3470ba08c6b0cb540a44d520b0613fd92af342f9e3f1bbcd9eb9591bdd2fa090922c66ec7783312807e36f97b98a0d1ba8c918be64845029aad059c35f96b53eea02d62d370127a83fdbf1ff016813bc35700e4af03230245d22acbcfd7692df71e20f870a81961b7daa43ef77ed98d05fed4a3170d3f6218cd5870c12ce45539f62fe0226e5b02f4280fc9cb8df2cb76ed890d261f32d0aef3333c7f3aa4b71d8f513bf7eb9a1de4eebb6e0fcb8d784b66ca6f4ba982b6e17c22731d5e43b7ae9a133b1e24167182a41265fd6af62b760d4aa25fcda851a2c0e6a5a11f2c4a73fc2e452a10d578fcc54558c2069792678a5c7b6c0e9a4eb54109d6d41238d043d8f40c3ed8bfa61d13301f24bb093dcd2d26715010a738565d204fe7699d4e2f22e82642a16cffb49d9c7cb7618bc9264312be8ed4614539e70c58b7deed204b003f0f17b01db3448f22cd354705c2d6cc5c92f5203d49f7bb55ce051f2a79ebfa85c532752c3c68581aaaa064a116038dcf7aa0781285178c561a445f0b605421e3fb55b875ac559e01d43cb5d34032a80daa0345f4a907543c3ad09109d685643ed75e384624f86a1f5f591523618743a19dd4049574af52f91159fe88bde647bf9e396ec2806072ecdb0a7fade59624b9d367fe95235088b1e24109a8fae2c4cb585ad27bc2d2cbd651a4995707e6767941cae458eacee8ded0b762611b85dd42d7f1761504cab8bbd9ee484c70666547a4292c32663a8fc5e84a9e6d805480101ec6d1c4a571740a23d847968d7422c30f641f84f17cda9427318bf9588f34695157f1d1259aea862c50fa1ec7c404a02236f7770ad1214b03a16d790d10c979b40d1b7445a5c5e316e145256661d0722d543146054a3d6a393b54444a2a8c"
						},
						{
							"features": "Plain",
							"commit": "08834fe21657d6e32dd33ce0a5dd53c7a70b25a36c37ef96a8bf3c70beb10a2ef9",
							"proof": "e46b4d5490e3a4160e49d0a43b8ddb2799efc5c21b7e7472e373f6c4a349eb073975dbecf49b9c6f8df6e82833a90ee9f1f7bd328550ae42c687478f836b507e07587e1c0f4e81fdbbcb89635afbfa93aa5967a02ec2f2e78508a84c19d09a8ff6001b2f09ea5fb58f3a65f8203d301796831168d7880cc73a383fa45ac76ab2de66f75acbf0a2dca29d5a7a42ae69a870d658e9c4bc5288c846f773c0b69596b892f53a8505c86b6fe3bcb3aa37a7eba2060b4735084a42f8601cf71482901f4ac055c773fd60230e848b8e7f65998ff91c9f9855e3ed36b5d301b5e5bbc1301cc3323ca3caa0c6b431528c88fa8f01e1b94dc3df8928b06f010a3e003488fcf3b8dd5686cb088c27382ece4320fdcf7fabb4bfecc0c04011f979533aa15498a42bc1726fd72a5388e9656390fd7baa084dc750ffde1ba7303664c0603dfe566864dfcdff43cd17c2b13977b544bcb95b3297be8f96515d27925277d5e14c4834130197741ffe45c49e9f7b2a3b517a89a0ee49eb04825c1dd7eb4f244779a92934c5a915183633db2993f1847a89f506b4aa4fba6b16c392b1b20ea695a89895e513cfbed2d11828806ecfc32d637a468d27238d6489deb0c634b33f21107fa37bab4ed59ce3418039d29adf5a5d178baf2752620d490a5e03fc1e85c79fdaccdf10dc50b561dc440bd498b6f1bfd6bda94147b130559280d92e1126cca5e7d04a9ae965f59e8831af5fd139cb486b1fedbce1f186fb1dfb211e73929349f9c9ef3799716f4a66ffbcd5aade8f1b950d29ee6983ce55a21705669f6d5fc94bf7c420ae3c0ae80ae55496f6516fd31f6f8196e918aa5384f925740375af027b488199ab892cc50f7827ee60d71823987dd67aa86d836c42ceb66cd96f85296c80510aa0e191fa8d973afdf2809590b524f3fdcb17e6077959724bcbec6291edf88d9e"
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
		]
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
				"num_participants": 2,
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
								"proof": "d24a6aa4f74ee607ef163713e2cfea0b435463ddf46392f6615c09519c8d76617cd3470ba08c6b0cb540a44d520b0613fd92af342f9e3f1bbcd9eb9591bdd2fa090922c66ec7783312807e36f97b98a0d1ba8c918be64845029aad059c35f96b53eea02d62d370127a83fdbf1ff016813bc35700e4af03230245d22acbcfd7692df71e20f870a81961b7daa43ef77ed98d05fed4a3170d3f6218cd5870c12ce45539f62fe0226e5b02f4280fc9cb8df2cb76ed890d261f32d0aef3333c7f3aa4b71d8f513bf7eb9a1de4eebb6e0fcb8d784b66ca6f4ba982b6e17c22731d5e43b7ae9a133b1e24167182a41265fd6af62b760d4aa25fcda851a2c0e6a5a11f2c4a73fc2e452a10d578fcc54558c2069792678a5c7b6c0e9a4eb54109d6d41238d043d8f40c3ed8bfa61d13301f24bb093dcd2d26715010a738565d204fe7699d4e2f22e82642a16cffb49d9c7cb7618bc9264312be8ed4614539e70c58b7deed204b003f0f17b01db3448f22cd354705c2d6cc5c92f5203d49f7bb55ce051f2a79ebfa85c532752c3c68581aaaa064a116038dcf7aa0781285178c561a445f0b605421e3fb55b875ac559e01d43cb5d34032a80daa0345f4a907543c3ad09109d685643ed75e384624f86a1f5f591523618743a19dd4049574af52f91159fe88bde647bf9e396ec2806072ecdb0a7fade59624b9d367fe95235088b1e24109a8fae2c4cb585ad27bc2d2cbd651a4995707e6767941cae458eacee8ded0b762611b85dd42d7f1761504cab8bbd9ee484c70666547a4292c32663a8fc5e84a9e6d805480101ec6d1c4a571740a23d847968d7422c30f641f84f17cda9427318bf9588f34695157f1d1259aea862c50fa1ec7c404a02236f7770ad1214b03a16d790d10c979b40d1b7445a5c5e316e145256661d0722d543146054a3d6a393b54444a2a8c"
							},
							{
								"commit": "08834fe21657d6e32dd33ce0a5dd53c7a70b25a36c37ef96a8bf3c70beb10a2ef9",
								"features": "Plain",
								"proof": "e46b4d5490e3a4160e49d0a43b8ddb2799efc5c21b7e7472e373f6c4a349eb073975dbecf49b9c6f8df6e82833a90ee9f1f7bd328550ae42c687478f836b507e07587e1c0f4e81fdbbcb89635afbfa93aa5967a02ec2f2e78508a84c19d09a8ff6001b2f09ea5fb58f3a65f8203d301796831168d7880cc73a383fa45ac76ab2de66f75acbf0a2dca29d5a7a42ae69a870d658e9c4bc5288c846f773c0b69596b892f53a8505c86b6fe3bcb3aa37a7eba2060b4735084a42f8601cf71482901f4ac055c773fd60230e848b8e7f65998ff91c9f9855e3ed36b5d301b5e5bbc1301cc3323ca3caa0c6b431528c88fa8f01e1b94dc3df8928b06f010a3e003488fcf3b8dd5686cb088c27382ece4320fdcf7fabb4bfecc0c04011f979533aa15498a42bc1726fd72a5388e9656390fd7baa084dc750ffde1ba7303664c0603dfe566864dfcdff43cd17c2b13977b544bcb95b3297be8f96515d27925277d5e14c4834130197741ffe45c49e9f7b2a3b517a89a0ee49eb04825c1dd7eb4f244779a92934c5a915183633db2993f1847a89f506b4aa4fba6b16c392b1b20ea695a89895e513cfbed2d11828806ecfc32d637a468d27238d6489deb0c634b33f21107fa37bab4ed59ce3418039d29adf5a5d178baf2752620d490a5e03fc1e85c79fdaccdf10dc50b561dc440bd498b6f1bfd6bda94147b130559280d92e1126cca5e7d04a9ae965f59e8831af5fd139cb486b1fedbce1f186fb1dfb211e73929349f9c9ef3799716f4a66ffbcd5aade8f1b950d29ee6983ce55a21705669f6d5fc94bf7c420ae3c0ae80ae55496f6516fd31f6f8196e918aa5384f925740375af027b488199ab892cc50f7827ee60d71823987dd67aa86d836c42ceb66cd96f85296c80510aa0e191fa8d973afdf2809590b524f3fdcb17e6077959724bcbec6291edf88d9e"
							}
						]
					},
					"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
				},
				"version_info": {
					"orig_version": 2,
					"version": 2,
					"block_header_version": 2
				}
			}
		}
	}
	# "#
	# , false, 5, true, true, false);
	```
	 */
	fn finalize_tx(&self, slate: VersionedSlate) -> Result<VersionedSlate, ErrorKind>;

	/**
	Networked version of [Owner::post_tx](struct.Owner.html#method.post_tx).

	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"id": 1,
		"method": "post_tx",
		"params": [
		{
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
						"proof": "d24a6aa4f74ee607ef163713e2cfea0b435463ddf46392f6615c09519c8d76617cd3470ba08c6b0cb540a44d520b0613fd92af342f9e3f1bbcd9eb9591bdd2fa090922c66ec7783312807e36f97b98a0d1ba8c918be64845029aad059c35f96b53eea02d62d370127a83fdbf1ff016813bc35700e4af03230245d22acbcfd7692df71e20f870a81961b7daa43ef77ed98d05fed4a3170d3f6218cd5870c12ce45539f62fe0226e5b02f4280fc9cb8df2cb76ed890d261f32d0aef3333c7f3aa4b71d8f513bf7eb9a1de4eebb6e0fcb8d784b66ca6f4ba982b6e17c22731d5e43b7ae9a133b1e24167182a41265fd6af62b760d4aa25fcda851a2c0e6a5a11f2c4a73fc2e452a10d578fcc54558c2069792678a5c7b6c0e9a4eb54109d6d41238d043d8f40c3ed8bfa61d13301f24bb093dcd2d26715010a738565d204fe7699d4e2f22e82642a16cffb49d9c7cb7618bc9264312be8ed4614539e70c58b7deed204b003f0f17b01db3448f22cd354705c2d6cc5c92f5203d49f7bb55ce051f2a79ebfa85c532752c3c68581aaaa064a116038dcf7aa0781285178c561a445f0b605421e3fb55b875ac559e01d43cb5d34032a80daa0345f4a907543c3ad09109d685643ed75e384624f86a1f5f591523618743a19dd4049574af52f91159fe88bde647bf9e396ec2806072ecdb0a7fade59624b9d367fe95235088b1e24109a8fae2c4cb585ad27bc2d2cbd651a4995707e6767941cae458eacee8ded0b762611b85dd42d7f1761504cab8bbd9ee484c70666547a4292c32663a8fc5e84a9e6d805480101ec6d1c4a571740a23d847968d7422c30f641f84f17cda9427318bf9588f34695157f1d1259aea862c50fa1ec7c404a02236f7770ad1214b03a16d790d10c979b40d1b7445a5c5e316e145256661d0722d543146054a3d6a393b54444a2a8c"
					},
					{
						"features": "Plain",
						"commit": "08834fe21657d6e32dd33ce0a5dd53c7a70b25a36c37ef96a8bf3c70beb10a2ef9",
						"proof": "e46b4d5490e3a4160e49d0a43b8ddb2799efc5c21b7e7472e373f6c4a349eb073975dbecf49b9c6f8df6e82833a90ee9f1f7bd328550ae42c687478f836b507e07587e1c0f4e81fdbbcb89635afbfa93aa5967a02ec2f2e78508a84c19d09a8ff6001b2f09ea5fb58f3a65f8203d301796831168d7880cc73a383fa45ac76ab2de66f75acbf0a2dca29d5a7a42ae69a870d658e9c4bc5288c846f773c0b69596b892f53a8505c86b6fe3bcb3aa37a7eba2060b4735084a42f8601cf71482901f4ac055c773fd60230e848b8e7f65998ff91c9f9855e3ed36b5d301b5e5bbc1301cc3323ca3caa0c6b431528c88fa8f01e1b94dc3df8928b06f010a3e003488fcf3b8dd5686cb088c27382ece4320fdcf7fabb4bfecc0c04011f979533aa15498a42bc1726fd72a5388e9656390fd7baa084dc750ffde1ba7303664c0603dfe566864dfcdff43cd17c2b13977b544bcb95b3297be8f96515d27925277d5e14c4834130197741ffe45c49e9f7b2a3b517a89a0ee49eb04825c1dd7eb4f244779a92934c5a915183633db2993f1847a89f506b4aa4fba6b16c392b1b20ea695a89895e513cfbed2d11828806ecfc32d637a468d27238d6489deb0c634b33f21107fa37bab4ed59ce3418039d29adf5a5d178baf2752620d490a5e03fc1e85c79fdaccdf10dc50b561dc440bd498b6f1bfd6bda94147b130559280d92e1126cca5e7d04a9ae965f59e8831af5fd139cb486b1fedbce1f186fb1dfb211e73929349f9c9ef3799716f4a66ffbcd5aade8f1b950d29ee6983ce55a21705669f6d5fc94bf7c420ae3c0ae80ae55496f6516fd31f6f8196e918aa5384f925740375af027b488199ab892cc50f7827ee60d71823987dd67aa86d836c42ceb66cd96f85296c80510aa0e191fa8d973afdf2809590b524f3fdcb17e6077959724bcbec6291edf88d9e"
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
		false
		]
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
	# , false, 5, true, true, true);
	```
	 */

	fn post_tx(&self, tx: TransactionV2, fluff: bool) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::cancel_tx](struct.Owner.html#method.cancel_tx).


	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "cancel_tx",
		"params": [null, "0436430c-2b02-624c-2032-570501212b00"],
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
	# , false, 5, true, true, false);
	```
	 */
	fn cancel_tx(&self, tx_id: Option<u32>, tx_slate_id: Option<Uuid>) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::get_stored_tx](struct.Owner.html#method.get_stored_tx).

	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "get_stored_tx",
		"id": 1,
		"params": [
			{
				"amount_credited": "999993000000",
				"amount_debited": "2000000000000",
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
				"tx_type": "TxSent"
			}
		]
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
	# , false, 5, true, true, false);
	```
	 */
	fn get_stored_tx(&self, tx: &TxLogEntry) -> Result<Option<TransactionV2>, ErrorKind>;

	/**
	Networked version of [Owner::verify_slate_messages](struct.Owner.html#method.verify_slate_messages).

	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "verify_slate_messages",
		"id": 1,
		"params": [ {
				"amount": "100000000000",
				"fee": "8000000",
				"height": "4",
				"id": "0436430c-2b02-624c-2032-570501212b00",
				"lock_height": "4",
				"num_participants": 2,
				"participant_data": [
				{
					"id": "0",
					"message": "my message",
					"message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b691cf3d54f980573a705782a74df2123f98547b49c40a013b5b69c7bca71aeee",
					"part_sig": null,
					"public_blind_excess": "027da3bc74bdfa9d57bc068ba0fbc3157cb8d03428806a75f7f28293cb1920e074",
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
							"features": "HeightLocked",
							"fee": "8000000",
							"lock_height": "4"
						}
						],
						"outputs": [
						{
							"commit": "097465837a7152837e0b12ed57b3cb9cfd65a3b1ece8d37333c3bd75ba80262012",
							"features": "Plain",
							"proof": "1ee0d5e3c4e7707e24557b04db846471db4f9ec621f2f6327a7749cac9911999ce880387e5d407a7a90926ada7393113699466db7f61f11df83dedc586b6c03e0a0d7147bbdcc7eb8edfde4a21f96cfd4cf3cfeead7d22d066e4aaf4bcc37e8e7e161a17d182f5c84888cafbf78c20c7686ac816a7dafffbbbfd65fcc318ba8d250954e796ee6ce24016051060ea14aa96ed67b2f2d091367d80b9468421e815019f85962c9f656e2e6835f1f63c9defc56742fb4e3ad38b94bf73e19b517fb67531524212efefbb88680e4428eda5a08eeeddddc8428678a2aaf85e239e0cfdda1877d2533620809f4623516083c9bcf171feb863e32385d01b3833cabe7672c4939a6013435c8bc9a268df537d58c919ec62cba0ed4972de30f2cda14d4514bb7406737eee50a12b32559f83c455edcc291a0390ebc4c15d5825f11e8268ddd7c8945b6a9aa4537352dbc5720c2db479c10761475670dec996f9876068f9f2774602360280856f2c688dea89617bb373bd68f9d8641ef06162a46b46591b8ddae2cc7a2baa20b5ddcd68f12b2c3c543e39ca13fd2ec1741700ab9c91dcfeeb8e5eb8f4e92ba53257b8ff6e08111e35d7bab7d346a37c53db1464a1d6f13d7acac5c48f9e283018f57ae05986fa5007f619a3a839a3b14d25dbd09a49af53613879baf9e0211618290dd7356235a699d0596549208b2b0858a004e4c7735e76e3f8bdbed53172ac6aff54670098b56ffc6cedac80b14cbdd9b58c394b22c1f73e312cef474d8935cbe4f53a9879a3fdedfd1aa4c7482df4c8787a1a09a149aeb5ef3df02462512137de64ddea077209c431049f2b1a95a9a1bd65f10288f5462dd0d39f580ae5550a27aedd1a8b503df12cf027f967e8478237e932a4bc1ae829fe461f146cd0607cfdd071c809b0fc131b977491d7431625154547955782f8293409"
						}
						]
					},
					"offset": "d202964900000000d302964900000000d402964900000000d502964900000000"
				},
				"version_info": {
					"orig_version": 2,
					"version": 2,
					"block_header_version": 2
				}
			}
		]
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
	# ,false, 0 ,false, false, false);
	```
	*/
	fn verify_slate_messages(&self, slate: VersionedSlate) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::restore](struct.Owner.html#method.restore).


	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "restore",
		"params": [],
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
	# , false, 1, false, false, false);
	```
	 */
	fn restore(&self) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::check_repair](struct.Owner.html#method.check_repair).


	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "check_repair",
		"params": [false],
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
	# , false, 1, false, false, false);
	```
	 */
	fn check_repair(&self, delete_unconfirmed: bool) -> Result<(), ErrorKind>;

	/**
	Networked version of [Owner::node_height](struct.Owner.html#method.node_height).


	```
	# kepler_wallet_api::doctest_helper_json_rpc_owner_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "node_height",
		"params": [],
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
				"height": "5",
				"updated_from_node": true
			}
		}
	}
	# "#
	# , false, 5, false, false, false);
	```
	 */
	fn node_height(&self) -> Result<NodeHeightResult, ErrorKind>;
}

impl<'a, L, C, K> OwnerRpc for Owner<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	fn accounts(&self) -> Result<Vec<AcctPathMapping>, ErrorKind> {
		Owner::accounts(self, None).map_err(|e| e.kind())
	}

	fn create_account_path(&self, label: &String) -> Result<Identifier, ErrorKind> {
		Owner::create_account_path(self, None, label).map_err(|e| e.kind())
	}

	fn set_active_account(&self, label: &String) -> Result<(), ErrorKind> {
		Owner::set_active_account(self, None, label).map_err(|e| e.kind())
	}

	fn retrieve_outputs(
		&self,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), ErrorKind> {
		Owner::retrieve_outputs(self, None, include_spent, refresh_from_node, tx_id)
			.map_err(|e| e.kind())
	}

	fn retrieve_txs(
		&self,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), ErrorKind> {
		Owner::retrieve_txs(self, None, refresh_from_node, tx_id, tx_slate_id).map_err(|e| e.kind())
	}

	fn retrieve_summary_info(
		&self,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), ErrorKind> {
		Owner::retrieve_summary_info(self, None, refresh_from_node, minimum_confirmations)
			.map_err(|e| e.kind())
	}

	fn init_send_tx(&self, args: InitTxArgs) -> Result<VersionedSlate, ErrorKind> {
		let slate = Owner::init_send_tx(self, None, args).map_err(|e| e.kind())?;
		let version = SlateVersion::V2;
		Ok(VersionedSlate::into_version(slate, version))
	}

	fn issue_invoice_tx(&self, args: IssueInvoiceTxArgs) -> Result<VersionedSlate, ErrorKind> {
		let slate = Owner::issue_invoice_tx(self, None, args).map_err(|e| e.kind())?;
		let version = SlateVersion::V2;
		Ok(VersionedSlate::into_version(slate, version))
	}

	fn process_invoice_tx(
		&self,
		in_slate: VersionedSlate,
		args: InitTxArgs,
	) -> Result<VersionedSlate, ErrorKind> {
		let out_slate = Owner::process_invoice_tx(self, None, &Slate::from(in_slate), args)
			.map_err(|e| e.kind())?;
		let version = SlateVersion::V2;
		Ok(VersionedSlate::into_version(out_slate, version))
	}

	fn finalize_tx(&self, in_slate: VersionedSlate) -> Result<VersionedSlate, ErrorKind> {
		let out_slate =
			Owner::finalize_tx(self, None, &Slate::from(in_slate)).map_err(|e| e.kind())?;
		let version = SlateVersion::V2;
		Ok(VersionedSlate::into_version(out_slate, version))
	}

	fn tx_lock_outputs(
		&self,
		slate: VersionedSlate,
		participant_id: usize,
	) -> Result<(), ErrorKind> {
		Owner::tx_lock_outputs(self, None, &Slate::from(slate), participant_id)
			.map_err(|e| e.kind())
	}

	fn cancel_tx(&self, tx_id: Option<u32>, tx_slate_id: Option<Uuid>) -> Result<(), ErrorKind> {
		Owner::cancel_tx(self, None, tx_id, tx_slate_id).map_err(|e| e.kind())
	}

	fn get_stored_tx(&self, tx: &TxLogEntry) -> Result<Option<TransactionV2>, ErrorKind> {
		Owner::get_stored_tx(self, None, tx)
			.map(|x| x.map(|y| TransactionV2::from(y)))
			.map_err(|e| e.kind())
	}

	fn post_tx(&self, tx: TransactionV2, fluff: bool) -> Result<(), ErrorKind> {
		Owner::post_tx(self, None, &Transaction::from(tx), fluff).map_err(|e| e.kind())
	}

	fn verify_slate_messages(&self, slate: VersionedSlate) -> Result<(), ErrorKind> {
		Owner::verify_slate_messages(self, None, &Slate::from(slate)).map_err(|e| e.kind())
	}

	fn restore(&self) -> Result<(), ErrorKind> {
		Owner::restore(self, None).map_err(|e| e.kind())
	}

	fn check_repair(&self, delete_unconfirmed: bool) -> Result<(), ErrorKind> {
		Owner::check_repair(self, None, delete_unconfirmed).map_err(|e| e.kind())
	}

	fn node_height(&self) -> Result<NodeHeightResult, ErrorKind> {
		Owner::node_height(self, None).map_err(|e| e.kind())
	}
}

/// helper to set up a real environment to run integrated doctests
pub fn run_doctest_owner(
	request: serde_json::Value,
	test_dir: &str,
	use_token: bool,
	blocks_to_mine: u64,
	perform_tx: bool,
	lock_tx: bool,
	finalize_tx: bool,
) -> Result<Option<serde_json::Value>, String> {
	use easy_jsonrpc_mw::Handler;
	use kepler_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};
	use kepler_wallet_impls::{DefaultLCProvider, DefaultWalletImpl};
	use kepler_wallet_libwallet::{api_impl, WalletInst};
	use kepler_wallet_util::kepler_keychain::ExtKeychain;

	use crate::core::global;
	use crate::core::global::ChainTypes;
	use kepler_wallet_util::kepler_util as util;

	use std::fs;
	use std::thread;

	util::init_test_logger();
	let _ = fs::remove_dir_all(test_dir);
	global::set_mining_mode(ChainTypes::AutomatedTesting);

	let mut wallet_proxy: WalletProxy<
		DefaultLCProvider<LocalWalletClient, ExtKeychain>,
		LocalWalletClient,
		ExtKeychain,
	> = WalletProxy::new(test_dir);
	let chain = wallet_proxy.chain.clone();

	let rec_phrase_1 = util::ZeroingString::from(
		"fat twenty mean degree forget shell check candy immense awful \
		 flame next during february bulb bike sun wink theory day kiwi embrace peace lunch",
	);
	let empty_string = util::ZeroingString::from("");

	let client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());
	let mut wallet1 =
		Box::new(DefaultWalletImpl::<LocalWalletClient>::new(client1.clone()).unwrap())
			as Box<
				dyn WalletInst<
					'static,
					DefaultLCProvider<LocalWalletClient, ExtKeychain>,
					LocalWalletClient,
					ExtKeychain,
				>,
			>;
	let lc = wallet1.lc_provider().unwrap();
	let _ = lc.set_top_level_directory(&format!("{}/wallet1", test_dir));
	lc.create_wallet(None, Some(rec_phrase_1), 32, empty_string.clone(), false)
		.unwrap();
	let mask1 = lc
		.open_wallet(None, empty_string.clone(), use_token, true)
		.unwrap();
	let wallet1 = Arc::new(Mutex::new(wallet1));

	if mask1.is_some() {
		println!("WALLET 1 MASK: {:?}", mask1.clone().unwrap());
	}

	wallet_proxy.add_wallet(
		"wallet1",
		client1.get_send_instance(),
		wallet1.clone(),
		mask1.clone(),
	);

	let rec_phrase_2 = util::ZeroingString::from(
		"hour kingdom ripple lunch razor inquiry coyote clay stamp mean \
		 sell finish magic kid tiny wage stand panther inside settle feed song hole exile",
	);
	let client2 = LocalWalletClient::new("wallet2", wallet_proxy.tx.clone());
	let mut wallet2 =
		Box::new(DefaultWalletImpl::<LocalWalletClient>::new(client2.clone()).unwrap())
			as Box<
				dyn WalletInst<
					'static,
					DefaultLCProvider<LocalWalletClient, ExtKeychain>,
					LocalWalletClient,
					ExtKeychain,
				>,
			>;
	let lc = wallet2.lc_provider().unwrap();
	let _ = lc.set_top_level_directory(&format!("{}/wallet2", test_dir));
	lc.create_wallet(None, Some(rec_phrase_2), 32, empty_string.clone(), false)
		.unwrap();
	let mask2 = lc
		.open_wallet(None, empty_string.clone(), use_token, true)
		.unwrap();
	let wallet2 = Arc::new(Mutex::new(wallet2));

	if mask2.is_some() {
		println!("WALLET 2 MASK: {:?}", mask2.clone().unwrap());
	}

	wallet_proxy.add_wallet(
		"wallet2",
		client2.get_send_instance(),
		wallet2.clone(),
		mask2.clone(),
	);

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// Mine a few blocks to wallet 1 so there's something to send
	for _ in 0..blocks_to_mine {
		let _ = test_framework::award_blocks_to_wallet(
			&chain,
			wallet1.clone(),
			(&mask1).as_ref(),
			1 as usize,
			false,
		);
		//update local outputs after each block, so transaction IDs stay consistent
		let mut w_lock = wallet1.lock();
		let w = w_lock.lc_provider().unwrap().wallet_inst().unwrap();
		let (wallet_refreshed, _) =
			api_impl::owner::retrieve_summary_info(&mut **w, (&mask1).as_ref(), true, 1).unwrap();
		assert!(wallet_refreshed);
	}

	if perform_tx {
		let amount = 1_000_000_000_000;
		let mut w_lock = wallet1.lock();
		let w = w_lock.lc_provider().unwrap().wallet_inst().unwrap();
		let args = InitTxArgs {
			src_acct_name: None,
			amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		let mut slate =
			api_impl::owner::init_send_tx(&mut **w, (&mask1).as_ref(), args, true).unwrap();
		println!("INITIAL SLATE");
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
		{
			let mut w_lock = wallet2.lock();
			let w2 = w_lock.lc_provider().unwrap().wallet_inst().unwrap();
			slate = api_impl::foreign::receive_tx(
				&mut **w2,
				(&mask2).as_ref(),
				&slate,
				None,
				None,
				true,
			)
			.unwrap();
			w2.close().unwrap();
		}
		// Spit out slate for input to finalize_tx
		if lock_tx {
			api_impl::owner::tx_lock_outputs(&mut **w, (&mask2).as_ref(), &slate, 0).unwrap();
		}
		println!("RECEIPIENT SLATE");
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
		if finalize_tx {
			slate = api_impl::owner::finalize_tx(&mut **w, (&mask2).as_ref(), &slate).unwrap();
			error!("FINALIZED TX SLATE");
			println!("{}", serde_json::to_string_pretty(&slate).unwrap());
		}
	}

	if perform_tx && lock_tx && finalize_tx {
		// mine to move the chain on
		let _ = test_framework::award_blocks_to_wallet(
			&chain,
			wallet1.clone(),
			(&mask1).as_ref(),
			3 as usize,
			false,
		);
	}

	let mut api_owner = Owner::new(wallet1);
	api_owner.doctest_mode = true;
	let res = if use_token {
		let owner_api = &api_owner as &dyn OwnerRpcS;
		owner_api.handle_request(request).as_option()
	} else {
		let owner_api = &api_owner as &dyn OwnerRpc;
		owner_api.handle_request(request).as_option()
	};
	let _ = fs::remove_dir_all(test_dir);
	Ok(res)
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_owner_assert_response {
	($request:expr, $expected_response:expr, $use_token:expr, $blocks_to_mine:expr, $perform_tx:expr, $lock_tx:expr, $finalize_tx:expr) => {
		// create temporary wallet, run jsonrpc request on owner api of wallet, delete wallet, return
		// json response.
		// In order to prevent leaking tempdirs, This function should not panic.

		// These cause LMDB to run out of disk space on CircleCI
		// disable for now on windows
		// TODO: Fix properly
		#[cfg(not(target_os = "windows"))]
			{
			use kepler_wallet_api::run_doctest_owner;
			use serde_json;
			use serde_json::Value;
			use tempfile::tempdir;

			let dir = tempdir().map_err(|e| format!("{:#?}", e)).unwrap();
			let dir = dir
				.path()
				.to_str()
				.ok_or("Failed to convert tmpdir path to string.".to_owned())
				.unwrap();

			let request_val: Value = serde_json::from_str($request).unwrap();
			let expected_response: Value = serde_json::from_str($expected_response).unwrap();

			let response = run_doctest_owner(
				request_val,
				dir,
				$use_token,
				$blocks_to_mine,
				$perform_tx,
				$lock_tx,
				$finalize_tx,
				)
			.unwrap()
			.unwrap();

			if response != expected_response {
				panic!(
					"(left != right) \nleft: {}\nright: {}",
					serde_json::to_string_pretty(&response).unwrap(),
					serde_json::to_string_pretty(&expected_response).unwrap()
				);
				}
			}
	};
}
