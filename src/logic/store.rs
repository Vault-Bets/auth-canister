use candid::{CandidType, Deserialize};
use std::collections::HashMap;
use std::cell::RefCell;
use ic_cdk::storage;

#[derive(CandidType, Clone, Deserialize)]
pub struct AccessToken {
    pub unencrypted_token: String,
    pub encrypted_token: String,
    pub created_at: u64,
}

#[derive(CandidType, Clone, Deserialize)]
pub struct UserData {
    pub seed: String,
    pub access_tokens: Vec<AccessToken>,
}

#[derive(CandidType, Clone, Default, Deserialize)]
pub struct State {
    pub users: HashMap<String, UserData>,
    pub private_key: Option<String>,
    pub public_key: Option<String>,
}

thread_local! {
    pub static STATE: RefCell<State> = RefCell::new(State::default());
}

impl State {
    pub fn insert_user(&mut self, user_key: String, user_data: UserData) {
        self.users.insert(user_key, user_data);
    }

    pub fn get_user(&self, user_key: &str) -> Option<&UserData> {
        self.users.get(user_key)
    }

    pub fn get_user_mut(&mut self, user_key: &str) -> Option<&mut UserData> {
        self.users.get_mut(user_key)
    }

    pub fn set_keys(&mut self, private_key: String, public_key: String) {
        self.private_key = Some(private_key);
        self.public_key = Some(public_key);
    }

    pub fn get_public_key(&self) -> Option<&String> {
        self.public_key.as_ref()
    }

    pub fn get_private_key(&self) -> Option<String> {
        self.private_key.clone()
    }
}

pub fn save_state() {
    STATE.with(|state| storage::stable_save((&*state.borrow(),)).unwrap());
}

pub fn load_state() {
    let (old_state,): (State,) = storage::stable_restore().unwrap();
    STATE.with(|state| *state.borrow_mut() = old_state);
}