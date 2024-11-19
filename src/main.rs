use std::{
    env,
    process::exit,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};
use rayon::prelude::*;
use sui_keys::key_derive::generate_new_key;
use sui_types::crypto::{SignatureScheme, SuiKeyPair, ToFromBytes};
use bech32::{ToBase32, encode}; // Bech32 library

fn main() {
    let args = env::args().skip(1).collect::<Vec<String>>();
    let mut args = args.into_iter();

    let mut prefix = args
        .next()
        .unwrap_or_else(|| {
            panic!("should define a prefix!");
        })
        .to_owned();
    prefix.insert_str(0, "0x");

    let word_size = args.next().unwrap_or("24".to_string());
    let prefix_length = prefix.len() - 2; // Ignore "0x" in the length

    let counter = Arc::new(AtomicUsize::new(0)); // Wrap the counter in an Arc
    let start_time = Instant::now(); // Track the start time

    // Logging thread
    {
        let counter = Arc::clone(&counter);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_secs(60));
            let generated = counter.load(Ordering::Relaxed);

            let elapsed_minutes = start_time.elapsed().as_secs() as f64 / 60.0;
            let speed_per_minute = generated as f64 / elapsed_minutes;

            let possible_combinations = 16u64.pow(prefix_length as u32); // 16^prefix_length
            let estimated_minutes = (possible_combinations as f64 / speed_per_minute).ceil();

            println!(
                "Addresses generated: {} | Speed: {:.2} per minute | Estimated time for match: {:.2} minutes",
                generated, speed_per_minute, estimated_minutes
            );
        });
    }

    // Parallel processing with Rayon
    let num_threads = num_cpus::get();
    println!("Using {} threads", num_threads);

    (0..num_threads).into_par_iter().for_each(|_| {
        let counter = Arc::clone(&counter);
        loop {
            let batch_size = 10_000; // Generate in batches
            for _ in 0..batch_size {
                let (sui_address, private_key, sig_scheme, mnemonic) = generate_new_key(
                    SignatureScheme::ED25519,
                    None,
                    Some(format!("word{}", word_size)),
                )
                .unwrap();

                counter.fetch_add(1, Ordering::Relaxed);

                if sui_address.to_string().starts_with(&prefix) {
                    // Add scheme flag to the private key bytes
                    let flag = match sig_scheme {
                        SignatureScheme::ED25519 => 0x00,
                        SignatureScheme::Secp256k1 => 0x01,
                        SignatureScheme::Secp256r1 => 0x02,
                        SignatureScheme::BLS12381 => panic!("BLS12381 is not supported for this application."),
                        SignatureScheme::MultiSig => panic!("MultiSig is not supported for this application."),
                        SignatureScheme::ZkLoginAuthenticator => panic!("ZkLoginAuthenticator is not supported."),
                    };
                    

                    // Match the specific keypair type and extract its private key bytes
                    let key_bytes = match private_key {
                        SuiKeyPair::Ed25519(kp) => kp.as_bytes().to_vec(),
                        SuiKeyPair::Secp256k1(kp) => kp.as_bytes().to_vec(),
                        SuiKeyPair::Secp256r1(kp) => kp.as_bytes().to_vec(),
                    };

                    // Prepend the flag to the private key bytes
                    let mut private_key_bytes = vec![flag];
                    private_key_bytes.extend_from_slice(&key_bytes);

                    // Bech32 encode the private key
                    let private_key_b32 = encode(
                        "suiprivkey",                         // Human-readable prefix
                        private_key_bytes.to_base32(),        // Convert to Base32
                        bech32::Variant::Bech32,
                    )
                    .expect("Failed to encode private key");

                    println!("Your sui address: {}", sui_address);
                    println!("Your mnemonic: {}", mnemonic);
                    println!("Your Bech32 private key: {}", private_key_b32);

                    exit(1); // Exit once the desired address is found
                }
            }
        }
    });
}
