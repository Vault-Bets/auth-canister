use base64::{engine::general_purpose, Engine as _};
use bip39::{Language, Mnemonic};
use ic_cdk::api::management_canister::main as management_canister;
use rand::rngs::StdRng;
use rand::SeedableRng;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::{pkcs8::LineEnding, Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

pub async fn generate_seed() -> Result<String, String> {
    let entropy = get_entropy().await?;
    let mnemonic: Mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|e| format!("Failed to generate mnemonic: {}", e))?;
    Ok(mnemonic.to_string())
}

pub async fn generate_otp() -> Result<String, String> {
    match management_canister::raw_rand().await {
        Ok((bytes,)) => {
            let mut otp = String::new();
            for &byte in bytes.iter().take(3) {
                let digit = byte % 10;
                otp.push_str(&digit.to_string());
            }
            Ok(otp)
        }
        Err(e) => Err(format!("Failed to generate OTP: {:?}", e)),
    }
}

pub async fn encrypt(public_key: &str, data: &str) -> String {
    let public_key_pem = general_purpose::STANDARD
        .decode(public_key)
        .expect("failed to decode public key");
    let public_key =
        RsaPublicKey::from_public_key_pem(std::str::from_utf8(&public_key_pem).unwrap())
            .expect("failed to parse public key");

    let seed = get_entropy_32().await.unwrap();
    let mut rng = StdRng::from_seed(seed);
    let enc_data = public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, data.as_bytes())
        .expect("failed to encrypt");

    general_purpose::STANDARD.encode(enc_data)
}

pub fn decrypt(private_key: &str, encrypted_data: &str) -> Result<String, String> {
    let private_key_pem = general_purpose::STANDARD
        .decode(private_key)
        .map_err(|e| format!("Failed to decode private key: {}", e))?;

    let private_key = RsaPrivateKey::from_pkcs8_pem(std::str::from_utf8(&private_key_pem).unwrap())
        .map_err(|e| format!("Failed to parse private key: {}", e))?;

    let encrypted_bytes = general_purpose::STANDARD
        .decode(encrypted_data)
        .map_err(|e| format!("Failed to decode encrypted data: {}", e))?;

    let decrypted_bytes = private_key
        .decrypt(Pkcs1v15Encrypt, &encrypted_bytes)
        .map_err(|e| format!("Failed to decrypt: {}", e))?;

    String::from_utf8(decrypted_bytes)
        .map_err(|e| format!("Failed to convert decrypted data to string: {}", e))
}

pub async fn generate_key_pair() -> (String, String) {
    let seed = get_entropy_32().await.unwrap();
    let mut rng = StdRng::from_seed(seed);
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let public_key = RsaPublicKey::from(&private_key);

    let private_key_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("failed to encode private key")
        .to_string();
    let public_key_pem = public_key
        .to_public_key_pem(LineEnding::LF)
        .expect("failed to encode public key");

    // Encode the PEM strings to base64 for easier storage
    let private_key_base64 = general_purpose::STANDARD.encode(private_key_pem);
    let public_key_base64 = general_purpose::STANDARD.encode(public_key_pem);

    (private_key_base64, public_key_base64)
}

async fn get_entropy() -> Result<[u8; 16], String> {
    match management_canister::raw_rand().await {
        Ok((bytes,)) => {
            let mut entropy = [0u8; 16];
            entropy.copy_from_slice(&bytes[..16]);
            Ok(entropy)
        }
        Err(e) => Err(format!("Failed to get random bytes: {:?}", e)),
    }
}

async fn get_entropy_32() -> Result<[u8; 32], String> {
    match management_canister::raw_rand().await {
        Ok((bytes,)) => {
            let mut entropy = [0u8; 32];
            entropy.copy_from_slice(&bytes[..32]);
            Ok(entropy)
        }
        Err(e) => Err(format!("Failed to get random bytes: {:?}", e)),
    }
}
