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
	self, BlockFees, CbData, ErrorKind, InitTxArgs, IssueInvoiceTxArgs, NodeClient,
	NodeVersionInfo, Slate, SlateVersion, VersionInfo, VersionedCoinbase, VersionedSlate,
	WalletLCProvider,
};
use crate::{Foreign, ForeignCheckMiddlewareFn};
use easy_jsonrpc_mw;

/// Public definition used to generate Foreign jsonrpc api.
/// * When running `kepler-wallet listen` with defaults, the V2 api is available at
/// `localhost:7415/v2/foreign`
/// * The endpoint only supports POST operations, with the json-rpc request as the body
#[easy_jsonrpc_mw::rpc]
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
	# ,false, 0, false, false);
	```
	*/
	fn check_version(&self) -> Result<VersionInfo, ErrorKind>;

	/**
	Networked Legacy (non-secure token) version of [Foreign::build_coinbase](struct.Foreign.html#method.build_coinbase).

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
					"proof": "f27469441ac377b0dedf1642481c33cef49355159aeae6a76ba2cc2cf5650af6c31f04863beef9ae91971f4b9fafe4af2309ef172b2e315f17513a1c6b84765b0f23adea48c0bcda629a5e3cdb407daf21458f44c763d2da6f89a81273054d7b1cb7574b6aac57debe4dbdf9e9a501113b1b86a911612d5689c58379403b74795fea2d4359c1d0839f411e1357e610e2853b4d9a2b78d72ef6cc10c642efdc72e5a0dd427d8ca49c473998438281e6784412125b14a38dcd5e00ef49508c977f967bb7deb371307da821e20ff127fd3ff23531ed975797b32ba3ea395f1bb7510d81d59b24f2bf65f387d3c10ff6085d145400c2f0770ef0a64aed00cc557d08a47a3d3db0c442a1cf6f054a740875e5ff205e710b401ca2416166097bc9c5e260df6b426ab51a2ca6af3e013ee499ad2bed67fc325c7eebb1717881d079522788bad90005318ef0f10e09c10d87bdc42b956342304ad5a9cd731903ea263b06e55b029e34e48cf2401fbd6fcd5c509a4ea9cbd72bb0c764398e3dabda2faecde33a7c5b59e1e5bbd1f0ebddee680ef9a16c12a67e12e689655e30c2ec364d4a5bdc000e9ada9dc6da5801f347acfec9a9f854ba78fddaefd777a989084a596eb83b2147046f35ddd473b00fada1eb724590a449f805e89d170017f87b1f747ff6b180e73617fcd6e7ce2b426b49b4a80beca2185c50efb0dc028c91535d430535f83bb692f0ece60fb121ce24de426a3e4bd8126f65553ff7d7e95588e4c17a228f5e26897433951fa672662ba744bd77d4846d9e8418d4c3acd490a9671583796ab58ffcc6b00f04f1a36b1691820c6f781b2b592e29f940b21e7073e92ded9d4a8de943115741e45d6e95b211f81282c72d682bb62cb5eef97cfcf108518da1bc1cafcb6d14e9ad65c3ff7311dbe922f04363ae3030e8e60bd814eac9f19a0456d4"
				}
			}
		}
	}
	# "#
	# ,false, 4, false, false);
	```
	*/

	fn build_coinbase(&self, block_fees: &BlockFees) -> Result<VersionedCoinbase, ErrorKind>;

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
	# ,false, 1 ,false, false);
	```
	*/
	fn verify_slate_messages(&self, slate: VersionedSlate) -> Result<(), ErrorKind>;

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
						"proof": "e126a0f9ccd961bccde0750b3fc76ef32234435516913f330813e626d62b377c358c91a151c90d7da93e66fbc29135f7a7eae816b02d8846311c3bd85109c34c0e348086c97e002e023185dc6bb1273e4ab7ead79f04e34760cf12a6df0381f2b6ccd98b284df8534421c20e3b2f2bebc44adcaab9d8cf556c44646d1b4631401cc07293670136b7fea53811f06c4a045748ba60d2018cae441f2ea497f2bae903e58bd06f1a1de85b13fbb4ac33684ccd6fa73c33fdd16cc1c43a035dc62f05d477bd7dab6dbd421269a500b7fa290c2010e2eff674377f65188b88b8eeee3373b88366d7ae7653980827ab090e2d04e22c3b5f4f02984a5ba1a47d21a7607e7f0e69ce157ec42199bbc66aa554eec1f03261eb3b3213f8f73d71d1fa6001cafb5347dc58b25c8cb3fa02ee6105b68d47d00bc6d19a145f4f29521bc203bde2b5dcde4aa9acde3a8958b144a72d20b48487558eee254c4c0ac405109ce36cfa636d0278b05c419c3c4ebc87ca5d1b8c7846aa5bb3a60022300ec09dc50d54c3125b3ac4d549e32c1a262e8082a0d26b8cb494428a669eac52af1428ab539d686115a3add1428da6a571a588e33bfa3e061645539c0c279a47fb48fe98bbc72f3f34ad6bfecbace9d4c2f0a9ada2176801b4987c2b1e61728ccb6cc4225af1897ab26eebd99429f27dbb36b52f8948b3f5dd63553223a8530cb47415f7010591e2ad7bc9f562c3b6cf120b604df8a2d5495f685b2c93a36090e2cc2754e20803a2e06288c00b5da2cec7483cc28d856343d7e8829e339d6fc537fb2a661af37ebb89262521e32a24a053aafd90614189d00ca8c208ae37cf25301ff4e27ab28c85c38aa90765cb43c521f5711a6abdf54bb909ca0b6299a455bf2ce763c9c1d5710c7d15128204ad4d0f270077cd6a0c0c0bddbbf36d8ffb0c651512875a8d41cd6894"
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
	# ,false, 5, true, false);
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
	# ,false, 5, false, true);
	```
	*/
	fn finalize_invoice_tx(&self, slate: VersionedSlate) -> Result<VersionedSlate, ErrorKind>;
}

impl<'a, L, C, K> ForeignRpc for Foreign<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	fn check_version(&self) -> Result<VersionInfo, ErrorKind> {
		Foreign::check_version(self).map_err(|e| e.kind())
	}

	fn build_coinbase(&self, block_fees: &BlockFees) -> Result<VersionedCoinbase, ErrorKind> {
		let cb: CbData = Foreign::build_coinbase(self, block_fees).map_err(|e| e.kind())?;
		Ok(VersionedCoinbase::into_version(cb, SlateVersion::V2))
	}

	fn verify_slate_messages(&self, slate: VersionedSlate) -> Result<(), ErrorKind> {
		Foreign::verify_slate_messages(self, &Slate::from(slate)).map_err(|e| e.kind())
	}

	fn receive_tx(
		&self,
		in_slate: VersionedSlate,
		dest_acct_name: Option<String>,
		message: Option<String>,
	) -> Result<VersionedSlate, ErrorKind> {
		let version = in_slate.version();
		let out_slate = Foreign::receive_tx(
			self,
			&Slate::from(in_slate),
			dest_acct_name.as_ref().map(String::as_str),
			message,
		)
		.map_err(|e| e.kind())?;
		Ok(VersionedSlate::into_version(out_slate, version))
	}

	fn finalize_invoice_tx(&self, in_slate: VersionedSlate) -> Result<VersionedSlate, ErrorKind> {
		let version = in_slate.version();
		let out_slate =
			Foreign::finalize_invoice_tx(self, &Slate::from(in_slate)).map_err(|e| e.kind())?;
		Ok(VersionedSlate::into_version(out_slate, version))
	}
}

fn test_check_middleware(
	_name: ForeignCheckMiddlewareFn,
	_node_version_info: Option<NodeVersionInfo>,
	_slate: Option<&Slate>,
) -> Result<(), libwallet::Error> {
	// TODO: Implement checks
	// return Err(ErrorKind::GenericError("Test Rejection".into()))?
	Ok(())
}

/// helper to set up a real environment to run integrated doctests
pub fn run_doctest_foreign(
	request: serde_json::Value,
	test_dir: &str,
	use_token: bool,
	blocks_to_mine: u64,
	init_tx: bool,
	init_invoice_tx: bool,
) -> Result<Option<serde_json::Value>, String> {
	use easy_jsonrpc_mw::Handler;
	use kepler_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};
	use kepler_wallet_impls::{DefaultLCProvider, DefaultWalletImpl};
	use kepler_wallet_libwallet::{api_impl, WalletInst};
	use kepler_wallet_util::kepler_keychain::ExtKeychain;

	use crate::core::global;
	use crate::core::global::ChainTypes;
	use kepler_wallet_util::kepler_util as util;

	use std::sync::Arc;
	use util::Mutex;

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
		let (wallet_refreshed, _) = api_impl::owner::retrieve_summary_info(
			wallet1.clone(),
			(&mask1).as_ref(),
			&None,
			true,
			1,
		)
		.unwrap();
		assert!(wallet_refreshed);
	}

	if init_invoice_tx {
		let amount = 1_000_000_000_000;
		let mut slate = {
			let mut w_lock = wallet2.lock();
			let w = w_lock.lc_provider().unwrap().wallet_inst().unwrap();
			let args = IssueInvoiceTxArgs {
				amount,
				..Default::default()
			};
			api_impl::owner::issue_invoice_tx(&mut **w, (&mask2).as_ref(), args, true).unwrap()
		};
		slate = {
			let mut w_lock = wallet1.lock();
			let w = w_lock.lc_provider().unwrap().wallet_inst().unwrap();
			let args = InitTxArgs {
				src_acct_name: None,
				amount: slate.amount,
				minimum_confirmations: 2,
				max_outputs: 500,
				num_change_outputs: 1,
				selection_strategy_is_use_all: true,
				..Default::default()
			};
			api_impl::owner::process_invoice_tx(&mut **w, (&mask1).as_ref(), &slate, args, true)
				.unwrap()
		};
		println!("INIT INVOICE SLATE");
		// Spit out slate for input to finalize_invoice_tx
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
	}

	if init_tx {
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
		let slate = api_impl::owner::init_send_tx(&mut **w, (&mask1).as_ref(), args, true).unwrap();
		println!("INIT SLATE");
		// Spit out slate for input to finalize_tx
		println!("{}", serde_json::to_string_pretty(&slate).unwrap());
	}

	let mut api_foreign = match init_invoice_tx {
		false => Foreign::new(wallet1, mask1, Some(test_check_middleware)),
		true => Foreign::new(wallet2, mask2, Some(test_check_middleware)),
	};
	api_foreign.doctest_mode = true;
	let foreign_api = &api_foreign as &dyn ForeignRpc;
	let res = foreign_api.handle_request(request).as_option();
	let _ = fs::remove_dir_all(test_dir);
	Ok(res)
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_foreign_assert_response {
	($request:expr, $expected_response:expr, $use_token:expr, $blocks_to_mine:expr, $init_tx:expr, $init_invoice_tx:expr) => {
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
			$use_token,
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
