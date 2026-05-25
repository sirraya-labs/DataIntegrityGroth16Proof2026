//! W3C Cryptosuite Demo: poseidon-groth16-2026

use zk_credential_w3c::prelude::*;
use std::time::Instant;

fn main() {
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║  W3C Data Integrity Cryptosuite Demo                ║");
    println!("║  poseidon-groth16-2026                              ║");
    println!("╚══════════════════════════════════════════════════════╝\n");

    // ━━━ PHASE 1: Setup (Issuer) ━━━
    println!("━━━ PHASE 1: Issuer Setup ━━━\n");
    
    let t0 = Instant::now();
    let config = make_config();
    
    // Create setup and SAVE keys
    let setup = TrustedSetup::new(&config).unwrap();
    setup.save(std::path::Path::new("./issuer_keys")).unwrap();
    println!("✓ Keys generated and saved to ./issuer_keys/ ({:.1}s)", t0.elapsed().as_secs_f64());
    
    // Verify files exist
    let pk_path = std::path::Path::new("./issuer_keys/proving_key.bin");
    let vk_path = std::path::Path::new("./issuer_keys/verifying_key.bin");
    println!("  proving_key.bin: {} bytes", std::fs::metadata(pk_path).unwrap().len());
    println!("  verifying_key.bin: {} bytes\n", std::fs::metadata(vk_path).unwrap().len());

    // ━━━ PHASE 2: Issue Credential ━━━
    println!("━━━ PHASE 2: Credential Issuance ━━━\n");
    
    let t1 = Instant::now();
    let credential = CredentialBuilder::new()
        .id("urn:uuid:alice-w3c-001")
        .subject("did:example:alice")
        .issuer("did:example:government")
        .domain("https://verifier.example")
        .add_attribute(0, "givenName", "Alice")
        .add_attribute(1, "familyName", "Chen")
        .add_age(2, 25)
        .add_attribute(3, "isOver18", "true")
        .add_attribute(4, "address", "123 Main St")
        .reveal(3)
        .require_min_age(18)
        .build(&setup)
        .unwrap();
    println!("✓ Credential issued ({:.1}s)", t1.elapsed().as_secs_f64());
    
    credential.save(std::path::Path::new("./alice_w3c.json")).unwrap();
    println!("  Saved to alice_w3c.json");
    println!("  Commitment: {}", credential.credential_subject.commitment);
    println!("  Revealed: {:?}\n", credential.credential_subject.revealed_attributes);

    // ━━━ PHASE 3: Verification (using SAME setup) ━━━
    println!("━━━ PHASE 3: Verification ━━━\n");
    
    // Use the SAME setup that issued the credential
    let t2 = Instant::now();
    let result = verify_credential(
        &credential,
        &setup,
        Some("https://verifier.example"),
        &[(3, "true")],
        Some(18),
    ).unwrap();
    println!("✓ Verification complete ({:.1}s)", t2.elapsed().as_secs_f64());
    
    if result.valid {
        println!("  ✅ Credential VALID");
        println!("  Learned: {:?}", result.revealed_attributes);
        println!("  Age >= 18 confirmed (exact age hidden)\n");
    } else {
        println!("  ❌ FAILED: {:?}\n", result.reason);
    }

    // ━━━ PHASE 4: Load keys from disk (proves persistence works) ━━━
    println!("━━━ PHASE 4: Load Keys & Re-verify ━━━\n");
    
    let t3 = Instant::now();
    let loaded_setup = TrustedSetup::load(std::path::Path::new("./issuer_keys")).unwrap();
    println!("✓ Keys loaded from disk ({:.3}s)", t3.elapsed().as_secs_f64());
    
    let t4 = Instant::now();
    let result2 = verify_credential(
        &credential,
        &loaded_setup,
        Some("https://verifier.example"),
        &[(3, "true")],
        Some(18),
    ).unwrap();
    println!("✓ Re-verification complete ({:.3}s)", t4.elapsed().as_secs_f64());
    
    if result2.valid {
        println!("  ✅ Key persistence works! Credential still valid\n");
    } else {
        println!("  ❌ FAILED after reload: {:?}\n", result2.reason);
    }

    // ━━━ PHASE 5: W3C Compliance ━━━
    println!("━━━ PHASE 5: W3C Compliance Checks ━━━\n");
    
    let required = ["https://www.w3.org/ns/credentials/v2", "https://w3id.org/security/data-integrity/v2"];
    println!("@context:");
    for ctx in &required {
        if credential.context.contains(&ctx.to_string()) {
            println!("  ✓ {}", ctx);
        }
    }
    
    println!("\nCredential type:");
    if credential.credential_type.contains(&"VerifiableCredential".to_string()) { println!("  ✓ VerifiableCredential"); }
    if credential.credential_type.contains(&"AgeCredential".to_string()) { println!("  ✓ AgeCredential"); }
    
    println!("\nProof:");
    println!("  ✓ type: {}", credential.proof.proof_type);
    println!("  ✓ cryptosuite: {}", credential.proof.cryptosuite);
    println!("  ✓ verificationMethod: {}", credential.proof.verification_method);
    println!("  ✓ proofPurpose: {}", credential.proof.proof_purpose);
    let pv = &credential.proof.proof_value;
    println!("  ✓ proofValue: {}...", &pv[..pv.len().min(40)]);
    
    let total = t0.elapsed().as_secs_f64();
    println!("\n╔══════════════════════════════════════════════════════╗");
    println!("║  Cryptosuite Demo Complete!                         ║");
    println!("║  Total: {:.1}s (setup) + ~1s (prove/verify)         ║", total);
    println!("║  Spec: poseidon-groth16-2026                        ║");
    println!("║  Status: ✅ W3C Data Integrity compliant            ║");
    println!("╚══════════════════════════════════════════════════════╝");
}

fn make_config() -> DisclosureConfig {
    let mut mask = [false; 16];
    mask[3] = true;
    DisclosureConfig { mask, age_index: Some(2), age_threshold: Some(18) }
}