//! Compute and verify a NIP-OA owner attestation without placing the owner
//! private key in a command argument or container image layer.

use std::{env, fs, process};

use buzz_sdk::nip_oa;
use nostr::{Keys, PublicKey};

fn fail(message: impl AsRef<str>) -> ! {
    eprintln!("compute-buzz-auth-tag: {}", message.as_ref());
    process::exit(1);
}

fn main() {
    let mut args = env::args_os();
    let program = args
        .next()
        .and_then(|value| value.into_string().ok())
        .unwrap_or_else(|| "compute-buzz-auth-tag".to_string());
    let owner_key_path = args.next().unwrap_or_else(|| {
        fail(format!(
            "usage: {program} <owner-private-key-file> <agent-pubkey-hex>"
        ))
    });
    let agent_pubkey_hex = args
        .next()
        .and_then(|value| value.into_string().ok())
        .unwrap_or_else(|| {
            fail(format!(
                "usage: {program} <owner-private-key-file> <agent-pubkey-hex>"
            ))
        });
    if args.next().is_some() {
        fail(format!(
            "usage: {program} <owner-private-key-file> <agent-pubkey-hex>"
        ));
    }

    let owner_secret = fs::read_to_string(&owner_key_path)
        .unwrap_or_else(|error| fail(format!("could not read owner private key: {error}")));
    let owner_keys = Keys::parse(owner_secret.trim())
        .unwrap_or_else(|error| fail(format!("invalid owner private key: {error}")));
    let agent_pubkey = PublicKey::from_hex(&agent_pubkey_hex)
        .unwrap_or_else(|error| fail(format!("invalid agent public key: {error}")));

    let auth_tag = nip_oa::compute_auth_tag(&owner_keys, &agent_pubkey, "")
        .unwrap_or_else(|error| fail(format!("could not compute auth tag: {error}")));
    let verified_owner = nip_oa::verify_auth_tag(&auth_tag, &agent_pubkey)
        .unwrap_or_else(|error| fail(format!("computed auth tag did not verify: {error}")));
    if verified_owner != owner_keys.public_key() {
        fail("computed auth tag resolved to the wrong owner");
    }

    println!("{auth_tag}");
}
