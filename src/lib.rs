#[cfg(test)]
mod tests {
    use std::{mem::size_of, num::ParseIntError, result::Result as StdResult};

    use fuel_core_types::{
        fuel_tx::{Output, Receipt, UtxoId},
        fuel_types::{Address, AssetId, Bytes32, Nonce},
    };
    use fuels::{
        accounts::{fuel_crypto::SecretKey, wallet::WalletUnlocked, ViewOnlyAccount},
        prelude::{
            setup_test_provider, Bech32Address, Contract, LoadConfiguration, Provider,
            ScriptTransaction, Signer, TxParameters, BASE_ASSET_ID,
        },
        test_helpers::{setup_single_asset_coins, setup_single_message, DEFAULT_COIN_AMOUNT},
        types::{
            coin::Coin,
            coin_type::CoinType,
            input::Input,
            message::Message,
            transaction_builders::{ScriptTransactionBuilder, TransactionBuilder},
            ContractId,
        },
    };
    use primitive_types::U256;

    /// Quickly converts the given hex string into a u8 vector
    fn decode_hex(s: &str) -> Vec<u8> {
        let data: StdResult<Vec<u8>, ParseIntError> = (2..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect();
        data.unwrap()
    }

    fn encode_hex(val: U256) -> [u8; 32] {
        let mut arr = [0u8; 32];
        val.to_big_endian(&mut arr);
        arr
    }

    fn load_contract() -> Contract {
        Contract::load_from(
            "./bridge-fungible-token/out/debug/bridge_fungible_token.bin",
            LoadConfiguration::default(),
        )
        .unwrap()
    }

    fn calculate_contract_id() -> ContractId {
        load_contract().contract_id()
    }

    const CONTRACT_MESSAGE_MIN_GAS: u64 = 10_000_000;

    struct TestSetup {
        provider: Provider,
        wallet: WalletUnlocked,
        message_input: Input,
        contract_input: Input,
        gas_input: Input,
    }

    fn generate_wallet() -> WalletUnlocked {
        const SIZE_SECRET_KEY: usize = size_of::<SecretKey>();
        const PADDING_BYTES: usize = SIZE_SECRET_KEY - size_of::<u64>();
        let mut secret_key: [u8; SIZE_SECRET_KEY] = [0; SIZE_SECRET_KEY];
        secret_key[PADDING_BYTES..].copy_from_slice(&(8320147306839812359u64).to_be_bytes());

        WalletUnlocked::new_from_private_key(
            SecretKey::try_from(secret_key.as_slice()).unwrap(),
            None,
        )
    }

    fn generate_gas_coin(owner: &Bech32Address) -> (Coin, Input) {
        let gas = setup_single_asset_coins(owner, BASE_ASSET_ID, 1, DEFAULT_COIN_AMOUNT)
            .pop()
            .unwrap();
        let gas_input = Input::resource_signed(CoinType::Coin(gas.clone()), 0);
        (gas, gas_input)
    }

    fn generate_message(recipient: &Bech32Address) -> (Message, Input) {
        let message_data = [
            (*calculate_contract_id()).to_vec(),
            decode_hex("0x00000000000000000000000000000000000000000000000000000000deadbeef"),
            decode_hex("0x0000000000000000000000008888888888888888888888888888888888888888"),
            vec![0; 32],
            encode_hex(U256::from(10)).to_vec(),
        ]
        .concat();

        let message: Message = setup_single_message(
            &Bech32Address::default(),
            recipient,
            100,
            Nonce::default(),
            message_data,
        );
        let message_input = Input::resource_signed(CoinType::Message(message.clone()), 0);

        (message, message_input)
    }

    fn generate_contract_input() -> Input {
        Input::contract(
            UtxoId::new(Bytes32::zeroed(), 0u8),
            Bytes32::zeroed(),
            Bytes32::zeroed(),
            Default::default(),
            calculate_contract_id(),
        )
    }

    async fn setup_test() -> TestSetup {
        let mut wallet = generate_wallet();

        let (gas, gas_input) = generate_gas_coin(wallet.address());
        let (message, message_input) = generate_message(wallet.address());
        let contract_input = generate_contract_input();

        let (provider, _) =
            setup_test_provider(vec![gas.clone()], vec![message.clone()], None, None).await;
        wallet.set_provider(provider.clone());

        TestSetup {
            wallet,
            message_input,
            contract_input,
            gas_input,
            provider,
        }
    }

    async fn deploy_contract(wallet: &WalletUnlocked) {
        load_contract()
            .deploy(&wallet.clone(), TxParameters::default())
            .await
            .unwrap();
    }

    fn build_tx(
        message: Input,
        contract: Input,
        gas: Input,
        wallet: &WalletUnlocked,
    ) -> ScriptTransaction {
        let tx_outputs = vec![
            Output::contract(1u8, Bytes32::zeroed(), Bytes32::zeroed()),
            Output::variable(Address::zeroed(), 0, AssetId::default()),
            Output::change(wallet.address().into(), 0, AssetId::default()),
        ];

        let tx_inputs: Vec<Input> = vec![message, contract, gas];

        let mut tx = ScriptTransactionBuilder::default()
            .set_script(
                std::fs::read("./message_relay_script/contract_message_script.bin").unwrap(),
            )
            .set_consensus_parameters(wallet.provider().unwrap().consensus_parameters())
            .set_gas_limit(CONTRACT_MESSAGE_MIN_GAS * 10)
            .set_inputs(tx_inputs)
            .set_outputs(tx_outputs)
            .build()
            .unwrap();

        wallet.sign_transaction(&mut tx).unwrap();

        tx
    }

    #[tokio::test]
    async fn corruption() {
        let TestSetup {
            provider,
            wallet,
            message_input,
            contract_input,
            gas_input,
        } = setup_test().await;

        deploy_contract(&wallet).await;

        let tx = build_tx(message_input, contract_input, gas_input, &wallet);

        let receipts = provider.send_transaction(&tx).await.unwrap();

        let receipts: Vec<String> = receipts
            .iter()
            .filter_map(|receipt| match receipt {
                Receipt::LogData { data, .. } => Some(format!("{:x?}", data)),
                _ => None,
            })
            .collect();

        match receipts.as_slice() {
            [log_before_struct, log_after_struct] => {
                assert_eq!(log_before_struct, "[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, de, ad, be, ef]");
                assert_eq!(log_before_struct, log_after_struct);
            }
            _ => panic!("Expected only two logs"),
        }
    }
}
