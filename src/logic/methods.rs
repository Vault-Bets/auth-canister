use ic_cdk_macros::*;

use super::store::{STATE, UserData, AccessToken, save_state, load_state};
use super::utils::{decrypt, encrypt, generate_key_pair, generate_otp, generate_seed};

#[init]
pub async fn init() {
    let (private_key, public_key) = generate_key_pair().await;
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.set_keys(private_key, public_key);
    });
}

#[pre_upgrade]
pub fn pre_upgrade() {
    save_state();
}

#[post_upgrade]
pub fn post_upgrade() {
    load_state();
}

#[update]
pub async fn register(user_key: String, user_pub_key: String) -> String {
    let seed = generate_seed().await.unwrap();
    let otp = generate_otp().await.unwrap();
    let encrypted_token = encrypt(&user_pub_key, &otp).await;

    let access_token = AccessToken {
        unencrypted_token: otp.clone(),
        encrypted_token: encrypted_token.clone(),
        created_at: ic_cdk::api::time(),
    };

    let user_data = UserData {
        seed,
        access_tokens: vec![access_token],
    };

    STATE.with(|state| {
        state.borrow_mut().insert_user(user_key, user_data);
    });

    encrypted_token
}


#[update]
pub async fn generate_access_token(user_key: String, user_pub_key: String) -> String {
    // Generate OTP outside of the closure
    let otp = generate_otp().await.unwrap();
    // Encrypt the OTP
    let encrypted_token = encrypt(&user_pub_key, &otp).await;

    // Update the state
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        if let Some(user_data) = state.get_user_mut(&user_key) {
            let access_token = AccessToken {
                unencrypted_token: otp.clone(),
                encrypted_token: encrypted_token.clone(),
                created_at: ic_cdk::api::time(),
            };

            user_data.access_tokens.push(access_token);
            encrypted_token
        } else {
            "User not found".to_string()
        }
    })
}


#[update]
pub fn authenticate(otp: String, access_token_retrieval_key: String) -> Option<String> {
    STATE.with(|state| {
        let mut state = state.borrow_mut();
        let private_key = state.get_private_key()?;
        
        let user_key = decrypt(&private_key, &access_token_retrieval_key).unwrap();

        let user_data = state.get_user_mut(&user_key)?;
        
        if let Some(index) = user_data.access_tokens.iter().position(|t| t.unencrypted_token == otp) {
            let _removed_token = user_data.access_tokens.remove(index);
            Some(user_data.seed.clone())
        } else {
            None
        }
    })
}

#[query]
fn get_public_key() -> Option<String> {
    STATE.with(|state| {
        state.borrow().get_public_key().cloned()
    })
}

// Add more methods as needed