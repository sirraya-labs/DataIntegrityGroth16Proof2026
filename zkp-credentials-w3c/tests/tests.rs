use zk_credential_w3c::prelude::*;

#[test]
fn test_full_flow() {
    let mut mask = [false; 16];
    mask[3] = true;

    let config = DisclosureConfig {
        mask,
        age_index: Some(2),
        age_threshold: Some(18),
    };

    let setup = TrustedSetup::new(&config).unwrap();

    let credential = CredentialBuilder::new()
        .subject("did:example:alice")
        .add_attribute(0, "name", "Alice")
        .add_age(2, 25)
        .add_attribute(3, "isOver18", "true")
        .reveal(3)
        .require_min_age(18)
        .build(&setup)
        .unwrap();

    let result = verify_credential(&credential, &setup, None).unwrap();
    assert!(result.valid);
}

#[test]
fn test_tamper_detection() {
    let mut mask = [false; 16];
    mask[3] = true;

    let config = DisclosureConfig {
        mask,
        age_index: Some(2),
        age_threshold: Some(18),
    };

    let setup = TrustedSetup::new(&config).unwrap();

    let credential = CredentialBuilder::new()
        .subject("did:example:alice")
        .add_attribute(0, "name", "Alice")
        .add_age(2, 25)
        .add_attribute(3, "isOver18", "true")
        .reveal(3)
        .require_min_age(18)
        .build(&setup)
        .unwrap();

    // Tamper with domain
    let json = credential.to_json().unwrap();
    let tampered = json.replace(
        "https://verifier.example",
        "https://evil.example"
    );
    let fake_cred = W3CCredential::from_json(&tampered).unwrap();
    
    let result = verify_credential(
        &fake_cred,
        &setup,
        Some("https://verifier.example")
    ).unwrap();
    
    assert!(!result.valid);
}

#[test]
fn test_underage_rejected() {
    let mut mask = [false; 16];
    mask[3] = true;

    let config = DisclosureConfig {
        mask,
        age_index: Some(2),
        age_threshold: Some(18),
    };

    let setup = TrustedSetup::new(&config).unwrap();

    // This should panic because 15 < 18
    let result = std::panic::catch_unwind(|| {
        CredentialBuilder::new()
            .subject("did:example:bob")
            .add_age(2, 15)
            .add_attribute(3, "isOver18", "true")
            .reveal(3)
            .require_min_age(18)
            .build(&setup)
            .unwrap()
    });

    assert!(result.is_err());
}

#[test]
fn test_key_persistence() {
    let mut mask = [false; 16];
    mask[3] = true;

    let config = DisclosureConfig {
        mask,
        age_index: Some(2),
        age_threshold: Some(18),
    };

    let setup = TrustedSetup::new(&config).unwrap();
    
    let dir = tempfile::tempdir().unwrap();
    setup.save(dir.path()).unwrap();
    
    let loaded = TrustedSetup::load(dir.path()).unwrap();
    
    // Test that loaded keys work
    let credential = CredentialBuilder::new()
        .subject("did:example:alice")
        .add_age(2, 25)
        .add_attribute(3, "isOver18", "true")
        .reveal(3)
        .require_min_age(18)
        .build(&loaded)
        .unwrap();

    let result = verify_credential(&credential, &loaded, None).unwrap();
    assert!(result.valid);
}