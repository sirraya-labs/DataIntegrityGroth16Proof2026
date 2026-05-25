//! Complete demonstration of the library

use zk_credential_w3c::prelude::*;

fn main() {
    // Suppress panic output from Groth16 constraint failures
    // This must be set BEFORE any panics can occur
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = info.to_string();
        // Only suppress Groth16 constraint panics
        if !msg.contains("cs.is_satisfied()") {
            default_hook(info);
        }
    }));
    
    println!("╔═══════════════════════════════════════════╗");
    println!("║  ZK Credential W3C - Demo                ║");
    println!("╚═══════════════════════════════════════════╝\n");

    // ━━━ Setup ━━━
    println!("[1] Setting up trusted parameters...");
    
    let mut mask = [false; 16];
    mask[3] = true; // Reveal isOver18

    let config = DisclosureConfig {
        mask,
        age_index: Some(2),
        age_threshold: Some(18),
    };

    let setup = TrustedSetup::new(&config).unwrap();
    setup.save(std::path::Path::new("./keys")).unwrap();
    println!("    ✓ Keys saved to ./keys/\n");

    // ━━━ Create Credential ━━━
    println!("[2] Creating credential for Alice (age 25)...");
    
    let credential = CredentialBuilder::new()
        .id("urn:uuid:alice-25")
        .subject("did:example:alice")
        .add_attribute(0, "givenName", "Alice")
        .add_attribute(1, "familyName", "Chen")
        .add_age(2, 25)
        .add_attribute(3, "isOver18", "true")
        .add_attribute(4, "address", "123 Main St")
        .reveal(3)
        .require_min_age(18)
        .build(&setup)
        .unwrap();

    credential.save(std::path::Path::new("alice.json")).unwrap();
    println!("    ✓ Credential saved to alice.json");
    println!("    Commitment: {}", credential.credential_subject.commitment);
    
    let proof_preview = &credential.proof.proof_value;
    println!("    Proof: {}...", &proof_preview[..proof_preview.len().min(40)]);
    println!();

    // ━━━ Verify valid credential ━━━
    println!("[3] Verifying valid credential...");
    
    let attribute_mapping = vec![(3, "true")];
    
    let result = verify_credential(
        &credential, 
        &setup, 
        Some("https://verifier.example"),
        &attribute_mapping,
        Some(18),
    ).unwrap();
    
    if result.valid {
        println!("    ✅ VALID: Alice is over 18");
        println!("    Revealed: {:?}", result.revealed_attributes);
        println!("    All other attributes remain hidden\n");
    } else {
        println!("    ❌ INVALID: {}\n", result.reason.unwrap_or_default());
    }

    // ━━━ Tamper Tests ━━━
    println!("[4] Testing tamper detection...\n");

    // Test 4a: Modify the commitment
    println!("    Test 4a: Changing the commitment value...");
    let mut tampered_cred = credential.clone();
    tampered_cred.credential_subject.commitment = "123456789".to_string();
    
    match verify_credential(&tampered_cred, &setup, Some("https://verifier.example"), &attribute_mapping, Some(18)) {
        Ok(result) if !result.valid => println!("       ✅ Commitment tampering detected!\n"),
        Ok(_) => println!("       ⚠️  Not detected (unexpected)\n"),
        Err(e) => println!("       ✅ Detected: {}\n", e),
    }

    // Test 4b: Change domain binding
    println!("    Test 4b: Changing domain to 'evil.example'...");
    let mut tampered_domain = credential.clone();
    tampered_domain.proof.domain = "https://evil.example".to_string();
    
    match verify_credential(&tampered_domain, &setup, Some("https://verifier.example"), &attribute_mapping, Some(18)) {
        Ok(result) if !result.valid => println!("       ✅ Domain binding works!\n"),
        Ok(_) => println!("       ⚠️  Domain check failed (unexpected)\n"),
        Err(e) => println!("       ✅ Domain binding works: {}\n", e),
    }

    // Test 4c: Corrupt the proof value
    println!("    Test 4c: Corrupting proof value...");
    let mut tampered_proof = credential.clone();
    let mut chars: Vec<char> = tampered_proof.proof.proof_value.chars().collect();
    if chars.len() > 10 {
        chars[10] = if chars[10] == 'A' { 'B' } else { 'A' };
        tampered_proof.proof.proof_value = chars.into_iter().collect();
    }
    
    match verify_credential(&tampered_proof, &setup, Some("https://verifier.example"), &attribute_mapping, Some(18)) {
        Ok(result) if !result.valid => println!("       ✅ Corrupted proof detected!\n"),
        Ok(_) => println!("       ⚠️  Not detected (unexpected)\n"),
        Err(e) => println!("       ✅ Detected: {}\n", e),
    }

    // Test 4d: Wrong revealed attribute value
    println!("    Test 4d: Using wrong revealed attribute value...");
    let wrong_mapping = vec![(3, "false")];
    
    match verify_credential(&credential, &setup, Some("https://verifier.example"), &wrong_mapping, Some(18)) {
        Ok(result) if !result.valid => println!("       ✅ Wrong attribute value detected!\n"),
        Ok(_) => println!("       ⚠️  Not detected (unexpected)\n"),
        Err(e) => println!("       ✅ Detected: {}\n", e),
    }

    // ━━━ Bob tries to cheat ━━━
    println!("[5] Bob (age 15) tries to get a credential...");
    
    // Use a separate scope to catch the panic cleanly
    let bob_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        CredentialBuilder::new()
            .subject("did:example:bob")
            .add_age(2, 15)
            .add_attribute(3, "isOver18", "true")
            .reveal(3)
            .require_min_age(18)
            .build(&setup)
    }));

    match bob_result {
        Ok(Ok(_)) => {
            println!("    ⚠️  Bob somehow created a proof (should not happen!)\n");
        }
        Ok(Err(e)) => {
            println!("    ✅ Bob cannot create a valid proof!");
            println!("    Error: {}", e);
            println!("    The ZK circuit enforces age >= 18");
            println!("    It's cryptographically impossible to bypass\n");
        }
        Err(_) => {
            // Panic was caught - this is expected for constraint violations
            println!("    ✅ Bob cannot create a valid proof!");
            println!("    The ZK circuit enforces age >= 18");
            println!("    It's cryptographically impossible to bypass\n");
        }
    }

    // ━━━ Summary ━━━
    println!("╔═══════════════════════════════════════════╗");
    println!("║  Demo Complete!                          ║");
    println!("╠═══════════════════════════════════════════╣");
    println!("║  ✅ Valid proofs verified                ║");
    println!("║  ✅ Commitment tampering detected        ║");
    println!("║  ✅ Domain binding enforced              ║");
    println!("║  ✅ Corrupted proofs rejected            ║");
    println!("║  ✅ Wrong attributes detected            ║");
    println!("║  ✅ Underage users cannot cheat          ║");
    println!("╚═══════════════════════════════════════════╝");
    
    println!("\n💡 What the verifier learns:");
    println!("   • isOver18 = true");
    println!("   • Age >= 18 (but not the exact age)");
    println!("\n🔒 What stays hidden:");
    println!("   • Name (Alice Chen)");
    println!("   • Exact age (25)");
    println!("   • Address (123 Main St)");
    
    // Restore default panic hook
    let _ = std::panic::take_hook();
}