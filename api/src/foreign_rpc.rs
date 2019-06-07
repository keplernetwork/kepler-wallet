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

//! JSON-RPC Stub generation for the Foreign API

use crate::keychain::Keychain;
use crate::libwallet::{
	BlockFees, CbData, ErrorKind, InitTxArgs, IssueInvoiceTxArgs, NodeClient, Slate, VersionInfo,
	VersionedSlate, WalletBackend,
};
use crate::Foreign;
use easy_jsonrpc;

/// Public definition used to generate Foreign jsonrpc api.
/// * When running `kepler-wallet listen` with defaults, the V2 api is available at
/// `localhost:7415/v2/foreign`
/// * The endpoint only supports POST operations, with the json-rpc request as the body
#[easy_jsonrpc::rpc]
pub trait ForeignRpc {
	/**
	Networked version of [Foreign::check_version](struct.Foreign.html#method.check_version).

	# Json rpc example

	```
	# kepler_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "check_version",
		"id": 1,
		"params": []
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"foreign_api_version": 2,
				"supported_slate_versions": [
					"V2"
				]
			}
		}
	}
	# "#
	# , 0, false, false);
	```
	*/
	fn check_version(&self) -> Result<VersionInfo, ErrorKind>;

	/**
	Networked version of [Foreign::build_coinbase](struct.Foreign.html#method.build_coinbase).

	# Json rpc example

	```
	# kepler_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "build_coinbase",
		"id": 1,
		"params": [
			{
				"fees": 0,
				"height": 0,
				"key_id": null
			}
		]
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
		"result": {
			"Ok": {
				"kernel": {
					"excess": "09b9553db8581804d5e64721b4410139dd3c2df02f578fe91f376cb86ab1d2b583",
					"excess_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841bdd1a837235392d75eb4a781aa23e0b04894f082cbbd15684b6e766a42aa4df9d",
					"features": "Coinbase",
					"fee": "0",
					"lock_height": "0"
				},
				"key_id": "0300000000000000000000000400000000",
				"output": {
					"commit": "09c217e925648404903e3c451557011e485aa8ed9571d5819fa188d794d6ea5db5",
					"features": "Coinbase",
					"proof": "35983019f7864d7804067fa0946fb3573e050da9335d91930c2f266ae193d0aa327efb95ad5aba4b0b124a161d7dfb5425ca6c7f769ccfee036a84d17d15536007050cb6532a79a18a5b1695af445d934281bb7cf1195eaab4a7704023744ba89b89f9ddf5d859b023b313ca7284d65b6fe5c2daa45e0c808a87bbcad84461a64a40437328b5d387863450ce6e699ef1ce8dc054db0bcc2b2c0e786d3e7ff218935f599e27cb84743b5d22c2cffc11e77b62b582357961287aa54507d5484872328e3e12d9131539231b98e33b1683fd14fb2fe996bcb4791437a9bbe00caa4f78aa62dce7f553e695e7552e6261f21c16412c5a2fcb06d86713c95db92e140dedf6ac813765b04fd28dbca102c1a31bcf3c397844f9036542fb953456e05d5fcc1780783eb8e04fd3a6612d6a8e4084b8f02ff9bb3d6e9cb2d8a4a4e2c468cb4d36ad864f9f6e5294c98e40c283be72cb900a2f018ded024e529339ba45bae6cea600ffa87f9a14e5116f24cd6f0aadf9d5d5a8aa70d31f12788a433f2b5c24cb58348cae0a7df5a277a1f168cea7e6566f4325ed6c3ac50550be0a752822f4e3c4db73740c911461ec66e3b38be02275d3cf6b39b6514c2d7cb1cc3f204597266348efe39f567bc79143c3768132c139c7aeb5757c83cc736ea4ec42fc8422308c5f237258ee5c8891a9d3ae982b7f8d0c9cbc2dd5e6e1968c65b91d5ff9a5f622b06004180a3829087e8adcae6049dd1fca2d1231129b1e597281e17e75a5b0f3fa820baf3b6451ca5fc4ba5775dad09f3dea7ffea1670ad4bd77e3f291d3b76e7a4d21e081b757d98b8122caaf707e3bf52108ac8da22a7eb6756c1f7a1998c13b3f2378dc90a8c1293357a69b2bf005c47997d69499d950ee39c5bf72e1956eb61c44cc83f271a18ac7711934abca1dae03043846ee4380f6f370850fb01268f5"
				}
			}
		}
	}
	# "#
	# , 4, false, false);
	```
	*/
	fn build_coinbase(&self, block_fees: &BlockFees) -> Result<CbData, ErrorKind>;

	/**
	Networked version of [Foreign::verify_slate_messages](struct.Foreign.html#method.verify_slate_messages).

	# Json rpc example

	```
	# kepler_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
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
	# ,1 ,false, false);
	```
	*/
	fn verify_slate_messages(&self, slate: &Slate) -> Result<(), ErrorKind>;

	/**
		Networked version of [Foreign::receive_tx](struct.Foreign.html#method.receive_tx).

	# Json rpc example

	```
	# kepler_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "receive_tx",
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
				}
			]
		},
		null,
		"Thanks, Yeastplume"
		]
	}
	# "#
	# ,
	# r#"
	{
	"id": 1,
	"jsonrpc": "2.0",
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
					"part_sig": null,
					"public_blind_excess": "03753c2cba849c4b14c70de681ff2e3fe1938bc3fe31562d7d0ebf4d5251a810e2",
					"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
				},
				{
					"id": "1",
					"message": "Thanks, Yeastplume",
		  "message_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b299337d8a8a8f26a6ddddb320daa4b5d6ee4269887925a03c546396c43e10482",
					"part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b07421863e9c1d176acb0e2a0caa5045a51e120966cfbf440d1fd33f8696329a4",
					"public_blind_excess": "023507d104bea90399bf8520fca12d87e0c01e863ed5b26ffab18b04d6f88913a7",
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
						"excess": "000000000000000000000000000000000000000000000000000000000000000000",
						"excess_sig": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
						"features": "Plain",
						"fee": "7000000",
						"lock_height": "0"
					}
					],
					"outputs": [
					{
						"commit": "08a07f26d5b85a5858114a9cc8b7569ba123a1551b9b714e37891c53a31c864ab6",
						"features": "Plain",
						"proof": "03a9318b92701464c651d333a8b723672e8dc72c18a5e47e3930f5d23d6c9b7d7b5074413c77b3ace6630590024bb5041ecefd5c4408cb17afce32e03cfc4f5d07226fce8b284cb1d97d83502117fdd5fccb385dfb0b0843344131147c0dd673fa8883c7b825614da827fb8c9a4a6678ada6b612c9d235e457e5a7166f426224f07323c3dccee8e7d304a1be47523d8bf30a5f4e1f7fa6f5eef9d2f255dc299932e172530176818506b8efbc451406da373f9a1ab0f05f4615b956171f80530e8625b79ecf03d91722f39760b8ac70de12bd3eefc6ab0c104e3fa00fc5ff3b7fbd916f2231d34ece89b8118c94db4ed33cf5faec5c525c547805d521499918716ed7fa1d5bc4271631d440a67ebb4203056b1e1abe44898588ed5dc22fd1193799c18d2cba315b1bc4c65f58437136b0e5a8ed6ae5637accc04e4fa62f3d1f7344f492a15b87ab367152d28b1010c70c7f744d5d37ae04eaac30b9add23888f67d88027882ee22ee914b5ee727fa515c706801db966a282c0f9d98e1bf3829a57e5404ca6f19cf17565d12cb4589c404e13781d78552bd0ef358d5d3b2d844372f4707bde26a4b793060b9ef8b3b213b741f345d1aa066efd4ae2231bf8f3179bd4081274705c3f33ab17175dc07f271d1aaa247c8e4d7555048b0958d452104e0cc42d80d82d28918c9e066a220da8f9ec4e5bad839ff8a0014d47616f0b2495db641fa2e8e15977fda32511e6a8c019b789d582820d492450164a41ba0e3bced0651e43f5acc760388caeb2841fc77c964e6babd0ebef1cd5f33ff5d548b5b5183e6fa375174f98ecb0ec31e11fc5e2df6f59aeea8abad95dafc2ad721df9f6d47cb37013f273218487079c7a43cb91fe901daf3d641638e00e6d9c6cce82b79d24b3b6d536d6da795769afecc6b3e02b4c43cabde76526bd7abc1b677710563c629"
					},
					{
						"commit": "08daa3f55556f7f66ef0633bbee5ccd0b670488395faa38fcf85ad180608e2e948",
						"features": "Plain",
						"proof": "d24a6aa4f74ee607ef163713e2cfea0b435463ddf46392f6615c09519c8d76617cd3470ba08c6b0cb540a44d520b0613fd92af342f9e3f1bbcd9eb9591bdd2fa090922c66ec7783312807e36f97b98a0d1ba8c918be64845029aad059c35f96b53eea02d62d370127a83fdbf1ff016813bc35700e4af03230245d22acbcfd7692df71e20f870a81961b7daa43ef77ed98d05fed4a3170d3f6218cd5870c12ce45539f62fe0226e5b02f4280fc9cb8df2cb76ed890d261f32d0aef3333c7f3aa4b71d8f513bf7eb9a1de4eebb6e0fcb8d784b66ca6f4ba982b6e17c22731d5e43b7ae9a133b1e24167182a41265fd6af62b760d4aa25fcda851a2c0e6a5a11f2c4a73fc2e452a10d578fcc54558c2069792678a5c7b6c0e9a4eb54109d6d41238d043d8f40c3ed8bfa61d13301f24bb093dcd2d26715010a738565d204fe7699d4e2f22e82642a16cffb49d9c7cb7618bc9264312be8ed4614539e70c58b7deed204b003f0f17b01db3448f22cd354705c2d6cc5c92f5203d49f7bb55ce051f2a79ebfa85c532752c3c68581aaaa064a116038dcf7aa0781285178c561a445f0b605421e3fb55b875ac559e01d43cb5d34032a80daa0345f4a907543c3ad09109d685643ed75e384624f86a1f5f591523618743a19dd4049574af52f91159fe88bde647bf9e396ec2806072ecdb0a7fade59624b9d367fe95235088b1e24109a8fae2c4cb585ad27bc2d2cbd651a4995707e6767941cae458eacee8ded0b762611b85dd42d7f1761504cab8bbd9ee484c70666547a4292c32663a8fc5e84a9e6d805480101ec6d1c4a571740a23d847968d7422c30f641f84f17cda9427318bf9588f34695157f1d1259aea862c50fa1ec7c404a02236f7770ad1214b03a16d790d10c979b40d1b7445a5c5e316e145256661d0722d543146054a3d6a393b54444a2a8c"
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
	# , 5, true, false);
	```
	*/
	fn receive_tx(
		&self,
		slate: VersionedSlate,
		dest_acct_name: Option<String>,
		message: Option<String>,
	) -> Result<VersionedSlate, ErrorKind>;

	/**

	Networked version of [Foreign::finalize_invoice_tx](struct.Foreign.html#method.finalize_invoice_tx).

	# Json rpc example

	```
	# kepler_wallet_api::doctest_helper_json_rpc_foreign_assert_response!(
	# r#"
	{
		"jsonrpc": "2.0",
		"method": "finalize_invoice_tx",
		"id": 1,
		"params": [{
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
					"id": "1",
					"public_blind_excess": "02b2efba85ab5cca24aa8c5347eaeba60e90afeab0f85a0ab118ecaf0bebfcbce1",
					"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
					"part_sig": null,
					"message": null,
					"message_sig": null
				},
				{
					"id": "0",
					"public_blind_excess": "0263b332a8e8296fbc957ba7214a89f18c1d8ec7b9d1171c14fea6c14ace472dbe",
					"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
					"part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b13208c47d60c96f7b1b73ea33056446d5ac5f304f86fa22eef4b50fae877f66f",
					"message": null,
					"message_sig": null
				}
			]
		}]
	}
	# "#
	# ,
	# r#"
	{
		"id": 1,
		"jsonrpc": "2.0",
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
						"id": "1",
						"message": null,
						"message_sig": null,
						"part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841ba0ffab8d4fe7a41283fe6ee9afbec172e81a9528cb2ce1f1b909a6dd41c61c64",
						"public_blind_excess": "02b2efba85ab5cca24aa8c5347eaeba60e90afeab0f85a0ab118ecaf0bebfcbce1",
						"public_nonce": "031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f"
					},
					{
						"id": "0",
						"message": null,
						"message_sig": null,
						"part_sig": "8f07ddd5e9f5179cff19486034181ed76505baaad53e5d994064127b56c5841b13208c47d60c96f7b1b73ea33056446d5ac5f304f86fa22eef4b50fae877f66f",
						"public_blind_excess": "0263b332a8e8296fbc957ba7214a89f18c1d8ec7b9d1171c14fea6c14ace472dbe",
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
	# , 5, false, true);
	```
	*/
	fn finalize_invoice_tx(&self, slate: &Slate) -> Result<Slate, ErrorKind>;
}

impl<W: ?Sized, C, K> ForeignRpc for Foreign<W, C, K>
where
	W: WalletBackend<C, K>,
	C: NodeClient,
	K: Keychain,
{
	fn check_version(&self) -> Result<VersionInfo, ErrorKind> {
		Foreign::check_version(self).map_err(|e| e.kind())
	}

	fn build_coinbase(&self, block_fees: &BlockFees) -> Result<CbData, ErrorKind> {
		Foreign::build_coinbase(self, block_fees).map_err(|e| e.kind())
	}

	fn verify_slate_messages(&self, slate: &Slate) -> Result<(), ErrorKind> {
		Foreign::verify_slate_messages(self, slate).map_err(|e| e.kind())
	}

	fn receive_tx(
		&self,
		slate: VersionedSlate,
		dest_acct_name: Option<String>,
		message: Option<String>,
	) -> Result<VersionedSlate, ErrorKind> {
		let version = slate.version();
		let slate: Slate = slate.into();
		let slate = Foreign::receive_tx(
			self,
			&slate,
			dest_acct_name.as_ref().map(String::as_str),
			message,
		)
		.map_err(|e| e.kind())?;

		Ok(VersionedSlate::into_version(slate, version))
	}

	fn finalize_invoice_tx(&self, slate: &Slate) -> Result<Slate, ErrorKind> {
		Foreign::finalize_invoice_tx(self, slate).map_err(|e| e.kind())
	}
}

/// helper to set up a real environment to run integrated doctests
pub fn run_doctest_foreign(
	request: serde_json::Value,
	test_dir: &str,
	blocks_to_mine: u64,
	init_tx: bool,
	init_invoice_tx: bool,
) -> Result<Option<serde_json::Value>, String> {
	use easy_jsonrpc::Handler;
	use kepler_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};
	use kepler_wallet_libwallet::api_impl;
	use kepler_wallet_util::kepler_keychain::ExtKeychain;

	use crate::core::global;
	use crate::core::global::ChainTypes;
	use kepler_wallet_util::kepler_util as util;

	use std::fs;
	use std::thread;

	util::init_test_logger();
	let _ = fs::remove_dir_all(test_dir);
	global::set_mining_mode(ChainTypes::AutomatedTesting);

	let mut wallet_proxy: WalletProxy<LocalWalletClient, ExtKeychain> = WalletProxy::new(test_dir);
	let chain = wallet_proxy.chain.clone();

	let rec_phrase_1 =
		"fat twenty mean degree forget shell check candy immense awful \
		 flame next during february bulb bike sun wink theory day kiwi embrace peace lunch";
	let client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());
	let wallet1 = test_framework::create_wallet(
		&format!("{}/wallet1", test_dir),
		client1.clone(),
		Some(rec_phrase_1),
	);
	wallet_proxy.add_wallet("wallet1", client1.get_send_instance(), wallet1.clone());

	let rec_phrase_2 =
		"hour kingdom ripple lunch razor inquiry coyote clay stamp mean \
		 sell finish magic kid tiny wage stand panther inside settle feed song hole exile";
	let client2 = LocalWalletClient::new("wallet2", wallet_proxy.tx.clone());
	let wallet2 = test_framework::create_wallet(
		&format!("{}/wallet2", test_dir),
		client2.clone(),
		Some(rec_phrase_2),
	);
	wallet_proxy.add_wallet("wallet2", client2.get_send_instance(), wallet2.clone());

	// Set the wallet proxy listener running
	thread::spawn(move || {
		if let Err(e) = wallet_proxy.run() {
			error!("Wallet Proxy error: {}", e);
		}
	});

	// Mine a few blocks to wallet 1 so there's something to send
	for _ in 0..blocks_to_mine {
		let _ = test_framework::award_blocks_to_wallet(&chain, wallet1.clone(), 1 as usize, false);
		//update local outputs after each block, so transaction IDs stay consistent
		let mut w = wallet1.lock();
		w.open_with_credentials().unwrap();
		let (wallet_refreshed, _) =
			api_impl::owner::retrieve_summary_info(&mut *w, true, 1).unwrap();
		assert!(wallet_refreshed);
		w.close().unwrap();
	}

	if init_invoice_tx {
		let amount = 1_000_000_000_000;
		let mut slate = {
			let mut w = wallet2.lock();
			w.open_with_credentials().unwrap();
			let args = IssueInvoiceTxArgs {
				amount,
				..Default::default()
			};
			api_impl::owner::issue_invoice_tx(&mut *w, args, true).unwrap()
		};
		slate = {
			let mut w = wallet1.lock();
			w.open_with_credentials().unwrap();
			let args = InitTxArgs {
				src_acct_name: None,
				amount: slate.amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				..Default::default()
			};
			api_impl::owner::process_invoice_tx(&mut *w, &slate, args, true).unwrap()
		};
		println!("INIT INVOICE SLATE");
		// Spit out slate for input to finalize_invoice_tx
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
	}

	if init_tx {
		let amount = 1_000_000_000_000;
		let mut w = wallet1.lock();
		w.open_with_credentials().unwrap();
		let args = InitTxArgs {
			src_acct_name: None,
			amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		let slate = api_impl::owner::init_send_tx(&mut *w, args, true).unwrap();
		println!("INIT SLATE");
		// Spit out slate for input to finalize_tx
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
	}

	let mut api_foreign = match init_invoice_tx {
		false => Foreign::new(wallet1.clone()),
		true => Foreign::new(wallet2.clone()),
	};
	api_foreign.doctest_mode = true;
	let foreign_api = &api_foreign as &dyn ForeignRpc;
	Ok(foreign_api.handle_request(request).as_option())
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_foreign_assert_response {
	($request:expr, $expected_response:expr, $blocks_to_mine:expr, $init_tx:expr, $init_invoice_tx:expr) => {
		// create temporary wallet, run jsonrpc request on owner api of wallet, delete wallet, return
		// json response.
		// In order to prevent leaking tempdirs, This function should not panic.
		use kepler_wallet_api::run_doctest_foreign;
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

		let response = run_doctest_foreign(
			request_val,
			dir,
			$blocks_to_mine,
			$init_tx,
			$init_invoice_tx,
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
	};
}
