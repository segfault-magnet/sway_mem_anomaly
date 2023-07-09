contract;

use std::{constants::ZERO_B256, inputs::input_message_data};

pub struct MessageData {
    token: b256,
    from: b256,
    to: Identity,
    amount: b256,
    len: u64,
}

abi MessageReceiver {
    fn process_message(msg_idx: u8);
}

impl MessageReceiver for Contract {
    fn process_message(msg_idx: u8) {
        let token: b256 = input_message_data(msg_idx, 32).into();
        log(token);
        let from: b256 = input_message_data(msg_idx, 32 + 32).into();
        let amount: b256 = input_message_data(msg_idx, 32 + 32 + 32 + 32).into();

        let message_data = MessageData {
            token,
            from,
            to: Identity::Address(Address::from(ZERO_B256)),
            amount,
            len: 160,
        };
        let another_token: b256 = message_data.token;
        log(another_token);
    }
}
