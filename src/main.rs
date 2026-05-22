// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// DataIntegrityGroth16Proof2026
// W3C Data Integrity Cryptosuite: poseidon-groth16-2026
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

use ark_bn254::{Bn254, Fr};
use ark_ff::{Field, PrimeField, Zero};
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_snark::SNARK;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Instant;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Protocol Constants
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const DOMAIN_SEP: &[u8] = b"DataIntegrityGroth16Proof2026::v1.0::";
const COMMITMENT_DOMAIN: &[u8] = b"Commitment";
const ATTRIBUTE_HASH_DOMAIN: &[u8] = b"AttributeHash";
const BLINDING_DERIVATION: &[u8] = b"BlindingDerivation";

const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 56;
const TOTAL_ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;
const STATE_WIDTH: usize = 3;
const RATE: usize = 2;
const NUM_ATTRIBUTES: usize = 16;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Poseidon Hash (Native)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

struct PoseidonParams {
    constants: Vec<Vec<Fr>>,
    mds: Vec<Vec<Fr>>,
}

fn get_params() -> &'static PoseidonParams {
    static PARAMS: OnceLock<PoseidonParams> = OnceLock::new();
    PARAMS.get_or_init(|| {
        let mut constants = Vec::with_capacity(TOTAL_ROUNDS);
        let mut hasher = Sha256::new();
        hasher.update(b"PoseidonBN254Constants");
        let mut seed = hasher.finalize();
        for _ in 0..TOTAL_ROUNDS {
            let mut round = Vec::with_capacity(STATE_WIDTH);
            for _ in 0..STATE_WIDTH {
                let mut inner = Sha256::new();
                inner.update(&seed);
                seed = inner.finalize();
                round.push(Fr::from_be_bytes_mod_order(&seed));
            }
            constants.push(round);
        }
        let mds = vec![
            vec![Fr::from(2u64), Fr::from(3u64), Fr::from(1u64)],
            vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)],
            vec![Fr::from(3u64), Fr::from(1u64), Fr::from(2u64)],
        ];
        PoseidonParams { constants, mds }
    })
}

fn sbox(x: &Fr) -> Fr {
    let x2 = x.square();
    let x4 = x2.square();
    *x * x4
}

fn full_round(state: &mut [Fr; STATE_WIDTH], round_idx: usize, params: &PoseidonParams) {
    let rc = &params.constants[round_idx];
    for i in 0..STATE_WIDTH {
        state[i] += rc[i];
    }
    for i in 0..STATE_WIDTH {
        state[i] = sbox(&state[i]);
    }
    let old = *state;
    for i in 0..STATE_WIDTH {
        state[i] = Fr::zero();
        for j in 0..STATE_WIDTH {
            state[i] += params.mds[i][j] * old[j];
        }
    }
}

fn partial_round(state: &mut [Fr; STATE_WIDTH], round_idx: usize, params: &PoseidonParams) {
    let rc = &params.constants[round_idx];
    for i in 0..STATE_WIDTH {
        state[i] += rc[i];
    }
    state[0] = sbox(&state[0]);
    let old = *state;
    for i in 0..STATE_WIDTH {
        state[i] = Fr::zero();
        for j in 0..STATE_WIDTH {
            state[i] += params.mds[i][j] * old[j];
        }
    }
}

fn poseidon_permutation(state: &mut [Fr; STATE_WIDTH]) {
    let params = get_params();
    for i in 0..FULL_ROUNDS / 2 {
        full_round(state, i, params);
    }
    for i in 0..PARTIAL_ROUNDS {
        partial_round(state, FULL_ROUNDS / 2 + i, params);
    }
    for i in 0..FULL_ROUNDS / 2 {
        full_round(state, FULL_ROUNDS / 2 + PARTIAL_ROUNDS + i, params);
    }
}

fn poseidon_sponge_hash(inputs: &[Fr]) -> Fr {
    let mut state = [Fr::zero(); STATE_WIDTH];
    let mut i = 0;
    while i < inputs.len() {
        for j in 0..RATE {
            if i < inputs.len() {
                state[j] += inputs[i];
                i += 1;
            }
        }
        poseidon_permutation(&mut state);
    }
    state[0]
}

fn poseidon_hash(inputs: &[Fr], domain_tag: &[u8]) -> Fr {
    let mut sha = Sha256::new();
    sha.update(DOMAIN_SEP);
    sha.update(domain_tag);
    let domain_fr = Fr::from_be_bytes_mod_order(&sha.finalize());
    let mut all = Vec::with_capacity(1 + inputs.len());
    all.push(domain_fr);
    all.extend_from_slice(inputs);
    poseidon_sponge_hash(&all)
}

fn hash_attribute(value: &str) -> Fr {
    let mut sha = Sha256::new();
    sha.update(DOMAIN_SEP);
    sha.update(ATTRIBUTE_HASH_DOMAIN);
    sha.update(value.as_bytes());
    Fr::from_be_bytes_mod_order(&sha.finalize())
}

fn create_commitment(attrs: &[Fr; NUM_ATTRIBUTES], blinding: &Fr) -> Fr {
    let mut inputs = Vec::with_capacity(NUM_ATTRIBUTES + 1);
    inputs.extend_from_slice(attrs);
    inputs.push(*blinding);
    poseidon_hash(&inputs, COMMITMENT_DOMAIN)
}

fn random_fr() -> Fr {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    Fr::from_le_bytes_mod_order(&bytes)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Deterministic Blinding Derivation 
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn generate_master_secret() -> [u8; 32] {
    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
    secret
}

fn derive_blinding(
    master_secret: &[u8; 32],
    credential_id: &str,
    attribute_index: usize,
) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_SEP);
    hasher.update(BLINDING_DERIVATION);
    hasher.update(master_secret);
    hasher.update(credential_id.as_bytes());
    hasher.update(&attribute_index.to_le_bytes());
    Fr::from_be_bytes_mod_order(&hasher.finalize())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Poseidon Circuit
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn sbox_circuit(x: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let x2 = x.square()?;
    let x4 = x2.square()?;
    Ok(&x4 * x)
}

fn full_round_circuit(
    state: &mut [FpVar<Fr>; STATE_WIDTH],
    round_idx: usize,
    params: &PoseidonParams,
) -> Result<(), SynthesisError> {
    let rc = &params.constants[round_idx];
    for i in 0..STATE_WIDTH {
        state[i] = &state[i] + FpVar::Constant(rc[i]);
    }
    for i in 0..STATE_WIDTH {
        state[i] = sbox_circuit(&state[i])?;
    }
    let old = state.clone();
    for i in 0..STATE_WIDTH {
        state[i] = FpVar::zero();
        for j in 0..STATE_WIDTH {
            state[i] = &state[i] + FpVar::Constant(params.mds[i][j]) * &old[j];
        }
    }
    Ok(())
}

fn partial_round_circuit(
    state: &mut [FpVar<Fr>; STATE_WIDTH],
    round_idx: usize,
    params: &PoseidonParams,
) -> Result<(), SynthesisError> {
    let rc = &params.constants[round_idx];
    for i in 0..STATE_WIDTH {
        state[i] = &state[i] + FpVar::Constant(rc[i]);
    }
    state[0] = sbox_circuit(&state[0])?;
    let old = state.clone();
    for i in 0..STATE_WIDTH {
        state[i] = FpVar::zero();
        for j in 0..STATE_WIDTH {
            state[i] = &state[i] + FpVar::Constant(params.mds[i][j]) * &old[j];
        }
    }
    Ok(())
}

fn poseidon_permutation_circuit(
    state: &mut [FpVar<Fr>; STATE_WIDTH],
) -> Result<(), SynthesisError> {
    let params = get_params();
    for i in 0..FULL_ROUNDS / 2 {
        full_round_circuit(state, i, params)?;
    }
    for i in 0..PARTIAL_ROUNDS {
        partial_round_circuit(state, FULL_ROUNDS / 2 + i, params)?;
    }
    for i in 0..FULL_ROUNDS / 2 {
        full_round_circuit(state, FULL_ROUNDS / 2 + PARTIAL_ROUNDS + i, params)?;
    }
    Ok(())
}

fn poseidon_sponge_hash_circuit(inputs: &[FpVar<Fr>]) -> Result<FpVar<Fr>, SynthesisError> {
    let mut state = [FpVar::zero(), FpVar::zero(), FpVar::zero()];
    let mut i = 0;
    while i < inputs.len() {
        for j in 0..RATE {
            if i < inputs.len() {
                state[j] = &state[j] + &inputs[i];
                i += 1;
            }
        }
        poseidon_permutation_circuit(&mut state)?;
    }
    Ok(state[0].clone())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Selective Disclosure Circuit
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

struct SelectiveDisclosureCircuit {
    pub attributes: [Option<Fr>; NUM_ATTRIBUTES],
    pub mask: [bool; NUM_ATTRIBUTES],
    pub blinding: Option<Fr>,
    pub expected_commitment: Option<Fr>,
    pub age_threshold: Option<Fr>,
    pub age_index: usize,
    pub domain_element: Fr,
}

impl ConstraintSynthesizer<Fr> for SelectiveDisclosureCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let domain_var = FpVar::Constant(self.domain_element);

        let mut revealed_vars = Vec::with_capacity(NUM_ATTRIBUTES);
        for i in 0..NUM_ATTRIBUTES {
            let val = if self.mask[i] {
                self.attributes[i]
            } else {
                Some(Fr::zero())
            };
            revealed_vars.push(FpVar::new_input(
                cs.clone(),
                || val.ok_or(SynthesisError::AssignmentMissing),
            )?);
        }

        let expected_commitment_var = FpVar::new_input(
            cs.clone(),
            || self.expected_commitment.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let age_threshold_var = FpVar::new_input(
            cs.clone(),
            || self.age_threshold.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let mut hidden_vars = Vec::new();
        for i in 0..NUM_ATTRIBUTES {
            if !self.mask[i] {
                hidden_vars.push(FpVar::new_witness(
                    cs.clone(),
                    || self.attributes[i].ok_or(SynthesisError::AssignmentMissing),
                )?);
            }
        }

        let blinding_var = FpVar::new_witness(
            cs.clone(),
            || self.blinding.ok_or(SynthesisError::AssignmentMissing),
        )?;

        let mut hash_inputs: Vec<FpVar<Fr>> = vec![domain_var];
        let mut hidden_idx = 0;
        let mut age_var: Option<FpVar<Fr>> = None;

        for i in 0..NUM_ATTRIBUTES {
            let attr_var = if self.mask[i] {
                let v = revealed_vars[i].clone();
                if i == self.age_index {
                    age_var = Some(v.clone());
                }
                v
            } else {
                let v = hidden_vars[hidden_idx].clone();
                hidden_idx += 1;
                if i == self.age_index {
                    age_var = Some(v.clone());
                }
                v
            };
            hash_inputs.push(attr_var);
        }
        hash_inputs.push(blinding_var);

        let computed = poseidon_sponge_hash_circuit(&hash_inputs)?;
        computed.enforce_equal(&expected_commitment_var)?;

        if let Some(age) = age_var {
            let delta = FpVar::new_witness(cs.clone(), || {
                let a = self.attributes[self.age_index]
                    .ok_or(SynthesisError::AssignmentMissing)?;
                let t = self.age_threshold
                    .ok_or(SynthesisError::AssignmentMissing)?;
                Ok(if a >= t { a - t } else { Fr::zero() })
            })?;

            age.enforce_equal(&(&age_threshold_var + &delta))?;

            let delta_bits = delta.to_bits_le()?;
            for bit in delta_bits.iter().skip(32) {
                bit.enforce_equal(&Boolean::constant(false))?;
            }
        }

        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Key & Proof Serialization
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn save_keys(
    pk: &ark_groth16::ProvingKey<Bn254>,
    vk: &ark_groth16::VerifyingKey<Bn254>,
    dir: &Path,
) {
    fs::create_dir_all(dir).expect("Failed to create key directory");

    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes)
        .expect("PK serialization failed");
    fs::write(dir.join("proving_key.bin"), &pk_bytes).expect("Failed to save PK");

    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)
        .expect("VK serialization failed");
    fs::write(dir.join("verifying_key.bin"), &vk_bytes).expect("Failed to save VK");

    println!("  Keys saved to: {}/", dir.display());
    println!("    proving_key.bin  ({} bytes)", pk_bytes.len());
    println!("    verifying_key.bin ({} bytes)", vk_bytes.len());
}

fn load_keys(
    dir: &Path,
) -> (
    ark_groth16::ProvingKey<Bn254>,
    ark_groth16::VerifyingKey<Bn254>,
) {
    let pk_bytes = fs::read(dir.join("proving_key.bin")).expect("Failed to read PK");
    let vk_bytes = fs::read(dir.join("verifying_key.bin")).expect("Failed to read VK");

    let pk = ark_groth16::ProvingKey::<Bn254>::deserialize_compressed(&pk_bytes[..])
        .expect("PK deserialization failed");
    let vk = ark_groth16::VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..])
        .expect("VK deserialization failed");

    (pk, vk)
}

fn save_proof(proof: &ark_groth16::Proof<Bn254>, path: &Path) {
    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .expect("Proof serialization failed");
    fs::write(path, &proof_bytes).expect("Failed to save proof");
    println!("  Proof saved: {} ({} bytes)", path.display(), proof_bytes.len());
}

fn load_proof(path: &Path) -> ark_groth16::Proof<Bn254> {
    let proof_bytes = fs::read(path).expect("Failed to read proof");
    ark_groth16::Proof::<Bn254>::deserialize_compressed(&proof_bytes[..])
        .expect("Proof deserialization failed")
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// W3C Output
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

mod base64url {
    pub fn encode(bytes: &[u8]) -> String {
        let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut result = String::new();
        
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
            let triple = (b0 << 16) | (b1 << 8) | b2;

            result.push(chars.chars().nth(((triple >> 18) & 0x3F) as usize).unwrap());
            result.push(chars.chars().nth(((triple >> 12) & 0x3F) as usize).unwrap());
            if chunk.len() > 1 {
                result.push(chars.chars().nth(((triple >> 6) & 0x3F) as usize).unwrap());
            }
            if chunk.len() > 2 {
                result.push(chars.chars().nth((triple & 0x3F) as usize).unwrap());
            }
        }
        result = result.trim_end_matches('A').to_string();
        result
    }
}

fn save_w3c_credential(
    credential_id: &str,
    proof: &ark_groth16::Proof<Bn254>,
    commitment: &Fr,
    path: &Path,
) {
    let mut bytes = Vec::new();
    proof.serialize_compressed(&mut bytes).expect("Serialization failed");
    let proof_value = base64url::encode(&bytes);

    let json = format!(
        r#"{{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/security/data-integrity/v2"
  ],
  "id": "{cid}",
  "type": ["VerifiableCredential", "AgeCredential"],
  "issuer": "did:example:government",
  "issuanceDate": "2026-05-21T00:00:00Z",
  "credentialSubject": {{
    "id": "did:example:alice",
    "commitment": "{comm}",
    "revealedAttributes": ["isOver18"]
  }},
  "proof": {{
    "type": "DataIntegrityProof",
    "cryptosuite": "poseidon-groth16-2026",
    "created": "2026-05-21T00:00:00Z",
    "verificationMethod": "did:example:government#poseidon-groth16-key-1",
    "proofPurpose": "assertionMethod",
    "proofValue": "{pv}",
    "domain": "https://verifier.example"
  }}
}}"#,
        cid = credential_id,
        comm = commitment,
        pv = proof_value,
    );

    fs::write(path, &json).expect("Failed to save W3C credential");
    println!("  W3C Credential saved: {}", path.display());
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Main
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn main() {
    println!("╔══════════════════════════════════════════════════════════════════╗");
    println!("║  W3C Data Integrity Cryptosuite: poseidon-groth16-2026          ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    let keys_dir = Path::new("./trusted_setup");
    let holder_dir = Path::new("./holder_files");

    for dir in &[keys_dir, holder_dir] {
        fs::create_dir_all(dir).expect("Failed to create directory");
    }

    // ━━━ PHASE 0: Setup ━━━
    println!("━━━ PHASE 0: TRUSTED SETUP ━━━\n");

    let credential_id = "urn:uuid:6a1676b8-b51f-11ed-937b-d76685a20ff5";
    let master_secret = generate_master_secret();
    let blinding = derive_blinding(&master_secret, credential_id, 0);

    let alice   = hash_attribute("Alice");
    let chen    = hash_attribute("Chen");
    let age_val = Fr::from(25u64);
    let over18  = hash_attribute("true");
    let address = hash_attribute("123 Main St");

    let mut attrs = [Fr::zero(); NUM_ATTRIBUTES];
    attrs[0] = alice;
    attrs[1] = chen;
    attrs[2] = age_val;
    attrs[3] = over18;
    attrs[4] = address;

    let commitment = create_commitment(&attrs, &blinding);
    println!("  Credential ID: {}", credential_id);
    println!("  Commitment:    {}\n", commitment);

    let mut mask = [false; NUM_ATTRIBUTES];
    mask[3] = true;

    let mut sha = Sha256::new();
    sha.update(DOMAIN_SEP);
    sha.update(COMMITMENT_DOMAIN);
    let domain_element = Fr::from_be_bytes_mod_order(&sha.finalize());

    let blank = SelectiveDisclosureCircuit {
        attributes: [None; NUM_ATTRIBUTES],
        mask,
        blinding: None,
        expected_commitment: None,
        age_threshold: None,
        age_index: 2,
        domain_element,
    };

    let mut rng = ark_std::rand::thread_rng();

    println!("  Running circuit-specific setup...");
    let t = Instant::now();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(blank, &mut rng)
        .expect("Setup failed");
    println!("  Setup completed in {:?}\n", t.elapsed());

    save_keys(&pk, &vk, keys_dir);

    // ━━━ PHASE 1: Prove ━━━
    println!("\n━━━ PHASE 1: GENERATE PROOF ━━━\n");

    println!("  Revealing:  isOver18 (index 3)");
    println!("  Hidden:     givenName, familyName, age, address");
    println!("  Predicate:  age >= 18 (age remains hidden)\n");

    let prover_blinding = derive_blinding(&master_secret, credential_id, 0);
    let prover_commitment = create_commitment(&attrs, &prover_blinding);

    assert_eq!(
        commitment, prover_commitment,
        "Commitment mismatch! Blinding derivation is broken."
    );
    println!("  ✓ Commitment verified (blinding derivation works)\n");

    let circuit = SelectiveDisclosureCircuit {
        attributes: attrs.map(Some),
        mask,
        blinding: Some(prover_blinding),
        expected_commitment: Some(prover_commitment),
        age_threshold: Some(Fr::from(18u64)),
        age_index: 2,
        domain_element,
    };

    println!("  Generating Groth16 proof...");
    let t = Instant::now();
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).expect("Proof generation failed");
    println!("  Proof generated in {:?}\n", t.elapsed());

    let proof_path = holder_dir.join("proof.bin");
    save_proof(&proof, &proof_path);
    save_w3c_credential(credential_id, &proof, &commitment, &holder_dir.join("w3c_credential.json"));

    // ━━━ PHASE 2: Verify ━━━
    println!("\n━━━ PHASE 2: VERIFY PROOF ━━━\n");

    println!("  Verifier receives:");
    println!("    - verifying_key.bin");
    println!("    - proof.bin");
    println!("    - isOver18 = true");
    println!("    - Commitment: {}", commitment);
    println!("    - Age threshold: 18\n");

    let mut public_inputs = vec![Fr::zero(); NUM_ATTRIBUTES];
    public_inputs[3] = attrs[3];
    public_inputs.push(commitment);
    public_inputs.push(Fr::from(18u64));

    println!("  Verifying proof...");
    let t = Instant::now();
    let is_valid =
        Groth16::<Bn254>::verify(&vk, &public_inputs, &proof).expect("Verification error");
    println!("  Verification completed in {:?}\n", t.elapsed());

    if is_valid {
        println!("╔══════════════════════════════════════════════════════════════════╗");
        println!("║  ✅ PROOF VERIFIED SUCCESSFULLY                                ║");
        println!("╠══════════════════════════════════════════════════════════════════╣");
        println!("║  Learned:    isOver18 = true, age >= 18                        ║");
        println!("║  Hidden:     Alice, Chen, 25, 123 Main St                      ║");
        println!("╚══════════════════════════════════════════════════════════════════╝");
    } else {
        println!("╔══════════════════════════════════════════════════════════════════╗");
        println!("║  ❌ PROOF VERIFICATION FAILED                                  ║");
        println!("╚══════════════════════════════════════════════════════════════════╝");
    }

    println!("\n━━━ FILES GENERATED ━━━\n");
    println!("  {}/proving_key.bin", keys_dir.display());
    println!("  {}/verifying_key.bin", keys_dir.display());
    println!("  {}/proof.bin", holder_dir.display());
    println!("  {}/w3c_credential.json", holder_dir.display());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_end_to_end() {
        let id = "test:1";
        let secret = generate_master_secret();
        let blinding = derive_blinding(&secret, id, 0);

        let mut attrs = [Fr::zero(); NUM_ATTRIBUTES];
        attrs[0] = hash_attribute("Alice");
        attrs[2] = Fr::from(25u64);
        attrs[3] = hash_attribute("true");

        let commitment = create_commitment(&attrs, &blinding);
        let mut mask = [false; NUM_ATTRIBUTES];
        mask[3] = true;

        let mut sha = Sha256::new();
        sha.update(DOMAIN_SEP);
        sha.update(COMMITMENT_DOMAIN);
        let de = Fr::from_be_bytes_mod_order(&sha.finalize());

        let blank = SelectiveDisclosureCircuit {
            attributes: [None; NUM_ATTRIBUTES], mask, blinding: None,
            expected_commitment: None, age_threshold: None, age_index: 2, domain_element: de,
        };

        let mut rng = ark_std::rand::thread_rng();
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(blank, &mut rng).unwrap();

        let circuit = SelectiveDisclosureCircuit {
            attributes: attrs.map(Some), mask, blinding: Some(blinding),
            expected_commitment: Some(commitment), age_threshold: Some(Fr::from(18u64)),
            age_index: 2, domain_element: de,
        };

        let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng).unwrap();

        let mut pi = vec![Fr::zero(); NUM_ATTRIBUTES];
        pi[3] = attrs[3];
        pi.push(commitment);
        pi.push(Fr::from(18u64));

        assert!(Groth16::<Bn254>::verify(&vk, &pi, &proof).unwrap());
    }

    #[test]
    fn test_blinding_deterministic() {
        let s = generate_master_secret();
        assert_eq!(derive_blinding(&s, "x", 0), derive_blinding(&s, "x", 0));
    }

    #[test]
    fn test_false_predicate_fails() {
        let id = "test:2";
        let secret = generate_master_secret();
        let blinding = derive_blinding(&secret, id, 0);

        let mut attrs = [Fr::zero(); NUM_ATTRIBUTES];
        attrs[2] = Fr::from(15u64); // Age 15 — should fail >= 18
        attrs[3] = hash_attribute("true");

        let commitment = create_commitment(&attrs, &blinding);
        let mut mask = [false; NUM_ATTRIBUTES];
        mask[3] = true;

        let mut sha = Sha256::new();
        sha.update(DOMAIN_SEP);
        sha.update(COMMITMENT_DOMAIN);
        let de = Fr::from_be_bytes_mod_order(&sha.finalize());

        let blank = SelectiveDisclosureCircuit {
            attributes: [None; NUM_ATTRIBUTES], mask, blinding: None,
            expected_commitment: None, age_threshold: None, age_index: 2, domain_element: de,
        };

        let mut rng = ark_std::rand::thread_rng();
        let (pk, _) = Groth16::<Bn254>::circuit_specific_setup(blank, &mut rng).unwrap();

        let circuit = SelectiveDisclosureCircuit {
            attributes: attrs.map(Some), mask, blinding: Some(blinding),
            expected_commitment: Some(commitment), age_threshold: Some(Fr::from(18u64)),
            age_index: 2, domain_element: de,
        };

        assert!(Groth16::<Bn254>::prove(&pk, circuit, &mut rng).is_err());
    }
}