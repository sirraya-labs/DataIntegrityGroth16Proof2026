//! Core cryptographic primitives
//! 
//! This module contains all the low-level crypto:
//! - Poseidon hash (native + circuit versions)
//! - Commitment scheme
//! - Selective disclosure ZK circuit
//! - Groth16 proving/verification

use ark_bn254::{Bn254, Fr};
use ark_ff::{Field, PrimeField, Zero};
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_snark::SNARK;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

use crate::error::CredentialError;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Constants
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub const NUM_ATTRIBUTES: usize = 16;
pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 56;
pub const TOTAL_ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;
pub const STATE_WIDTH: usize = 3;
pub const RATE: usize = 2;

const DOMAIN_SEP: &[u8] = b"DataIntegrityGroth16Proof2026::v1.0::";
const COMMITMENT_DOMAIN: &[u8] = b"Commitment";
const ATTRIBUTE_HASH_DOMAIN: &[u8] = b"AttributeHash";
const BLINDING_DERIVATION: &[u8] = b"BlindingDerivation";

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Poseidon Hash Parameters
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct PoseidonParams {
    pub constants: Vec<Vec<Fr>>,
    pub mds: Vec<Vec<Fr>>,
}

pub fn get_poseidon_params() -> &'static PoseidonParams {
    static PARAMS: OnceLock<PoseidonParams> = OnceLock::new();
    PARAMS.get_or_init(generate_params)
}

fn generate_params() -> PoseidonParams {
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
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Poseidon Hash - Native
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn sbox(x: &Fr) -> Fr {
    let x2 = x.square();
    let x4 = x2.square();
    *x * x4
}

fn full_round(state: &mut [Fr; STATE_WIDTH], round_idx: usize, params: &PoseidonParams) {
    let rc = &params.constants[round_idx];
    for i in 0..STATE_WIDTH {
        state[i] += rc[i];
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
    let params = get_poseidon_params();
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

/// Hash a sequence of field elements with domain separation
pub fn poseidon_hash(inputs: &[Fr], domain_tag: &[u8]) -> Fr {
    let mut sha = Sha256::new();
    sha.update(DOMAIN_SEP);
    sha.update(domain_tag);
    let domain_fr = Fr::from_be_bytes_mod_order(&sha.finalize());
    
    let mut all = Vec::with_capacity(1 + inputs.len());
    all.push(domain_fr);
    all.extend_from_slice(inputs);
    poseidon_sponge_hash(&all)
}

/// Hash a string attribute value
pub fn hash_attribute(value: &str) -> Fr {
    let mut sha = Sha256::new();
    sha.update(DOMAIN_SEP);
    sha.update(ATTRIBUTE_HASH_DOMAIN);
    sha.update(value.as_bytes());
    Fr::from_be_bytes_mod_order(&sha.finalize())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Commitment Scheme
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Create a Pedersen commitment to a set of attributes
pub fn create_commitment(attrs: &[Fr; NUM_ATTRIBUTES], blinding: &Fr) -> Fr {
    let mut inputs = Vec::with_capacity(NUM_ATTRIBUTES + 1);
    inputs.extend_from_slice(attrs);
    inputs.push(*blinding);
    poseidon_hash(&inputs, COMMITMENT_DOMAIN)
}

/// Derive a blinding factor deterministically
pub fn derive_blinding(
    master_secret: &[u8; 32],
    credential_id: &str,
) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_SEP);
    hasher.update(BLINDING_DERIVATION);
    hasher.update(master_secret);
    hasher.update(credential_id.as_bytes());
    Fr::from_be_bytes_mod_order(&hasher.finalize())
}

/// Generate a random master secret
pub fn generate_master_secret() -> [u8; 32] {
    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
    secret
}

/// Get the domain element for the commitment domain
pub fn get_commitment_domain() -> Fr {
    let mut sha = Sha256::new();
    sha.update(DOMAIN_SEP);
    sha.update(COMMITMENT_DOMAIN);
    Fr::from_be_bytes_mod_order(&sha.finalize())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Poseidon Circuit (for ZK)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn sbox_circuit(x: &FpVar<Fr>) -> std::result::Result<FpVar<Fr>, SynthesisError> {
    let x2 = x.square()?;
    let x4 = x2.square()?;
    Ok(&x4 * x)
}

fn full_round_circuit(
    state: &mut [FpVar<Fr>; STATE_WIDTH],
    round_idx: usize,
    params: &PoseidonParams,
) -> std::result::Result<(), SynthesisError> {
    let rc = &params.constants[round_idx];
    for i in 0..STATE_WIDTH {
        state[i] = &state[i] + FpVar::Constant(rc[i]);
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
) -> std::result::Result<(), SynthesisError> {
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
) -> std::result::Result<(), SynthesisError> {
    let params = get_poseidon_params();
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

fn poseidon_sponge_hash_circuit(inputs: &[FpVar<Fr>]) -> std::result::Result<FpVar<Fr>, SynthesisError> {
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

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Selective Disclosure Circuit
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Configuration for what to prove about the attributes
#[derive(Clone)]
pub struct DisclosureConfig {
    /// Which attributes are publicly revealed (true = revealed)
    pub mask: [bool; NUM_ATTRIBUTES],
    /// Index of the age attribute (for age verification)
    pub age_index: Option<usize>,
    /// Minimum age threshold (if age verification is needed)
    pub age_threshold: Option<u64>,
}

impl Default for DisclosureConfig {
    fn default() -> Self {
        Self {
            mask: [false; NUM_ATTRIBUTES],
            age_index: None,
            age_threshold: None,
        }
    }
}

/// The ZK circuit that proves selective disclosure
pub struct SelectiveDisclosureCircuit {
    pub attributes: [Option<Fr>; NUM_ATTRIBUTES],
    pub mask: [bool; NUM_ATTRIBUTES],
    pub blinding: Option<Fr>,
    pub expected_commitment: Option<Fr>,
    pub age_threshold: Option<Fr>,
    pub age_index: usize,
    pub domain_element: Fr,
}

impl ConstraintSynthesizer<Fr> for SelectiveDisclosureCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> std::result::Result<(), SynthesisError> {
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

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Key Management
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// The trusted setup keys for creating and verifying proofs
pub struct TrustedSetup {
    pub proving_key: ark_groth16::ProvingKey<Bn254>,
    pub verifying_key: ark_groth16::VerifyingKey<Bn254>,
}

impl TrustedSetup {
    /// Create a new trusted setup from a disclosure configuration
    pub fn new(config: &DisclosureConfig) -> std::result::Result<Self, CredentialError> {
        let domain_element = get_commitment_domain();
        
        let blank = SelectiveDisclosureCircuit {
            attributes: [None; NUM_ATTRIBUTES],
            mask: config.mask,
            blinding: None,
            expected_commitment: None,
            age_threshold: None,
            age_index: config.age_index.unwrap_or(0),
            domain_element,
        };

        let mut rng = ark_std::rand::thread_rng();
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(blank, &mut rng)
            .map_err(|e| CredentialError::SetupFailed(e.to_string()))?;

        Ok(Self { proving_key: pk, verifying_key: vk })
    }

    /// Save keys to directory
    pub fn save(&self, dir: &std::path::Path) -> std::result::Result<(), CredentialError> {
        std::fs::create_dir_all(dir).map_err(CredentialError::IoError)?;
        
        let mut pk_bytes = Vec::new();
        self.proving_key.serialize_compressed(&mut pk_bytes)
            .map_err(|e| CredentialError::SerializationError(e.to_string()))?;
        std::fs::write(dir.join("proving_key.bin"), &pk_bytes)
            .map_err(CredentialError::IoError)?;

        let mut vk_bytes = Vec::new();
        self.verifying_key.serialize_compressed(&mut vk_bytes)
            .map_err(|e| CredentialError::SerializationError(e.to_string()))?;
        std::fs::write(dir.join("verifying_key.bin"), &vk_bytes)
            .map_err(CredentialError::IoError)?;

        Ok(())
    }

    /// Load keys from directory  
    pub fn load(dir: &std::path::Path) -> std::result::Result<Self, CredentialError> {
        use std::io::Read;
        
        let pk_path = dir.join("proving_key.bin");
        let vk_path = dir.join("verifying_key.bin");
        
        // Read files
        let mut pk_file = std::fs::File::open(&pk_path)
            .map_err(|e| CredentialError::IoError(e))?;
        let mut pk_bytes = Vec::new();
        pk_file.read_to_end(&mut pk_bytes)
            .map_err(|e| CredentialError::IoError(e))?;
        
        let mut vk_file = std::fs::File::open(&vk_path)
            .map_err(|e| CredentialError::IoError(e))?;
        let mut vk_bytes = Vec::new();
        vk_file.read_to_end(&mut vk_bytes)
            .map_err(|e| CredentialError::IoError(e))?;

        // Deserialize
        let pk = ark_groth16::ProvingKey::<Bn254>::deserialize_compressed(&pk_bytes[..])
            .map_err(|e| CredentialError::SerializationError(e.to_string()))?;
        let vk = ark_groth16::VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..])
            .map_err(|e| CredentialError::SerializationError(e.to_string()))?;

        Ok(Self { proving_key: pk, verifying_key: vk })
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Proving & Verification
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Generate a zero-knowledge proof
pub fn generate_proof(
    setup: &TrustedSetup,
    attributes: &[Fr; NUM_ATTRIBUTES],
    blinding: Fr,
    commitment: Fr,
    config: &DisclosureConfig,
) -> std::result::Result<ark_groth16::Proof<Bn254>, CredentialError> {
    // Pre-check: validate age constraint
    if let (Some(age_idx), Some(threshold)) = (config.age_index, config.age_threshold) {
        if age_idx < NUM_ATTRIBUTES {
            let age = attributes[age_idx];
            let threshold_fr = Fr::from(threshold);
            if age < threshold_fr {
                return Err(CredentialError::ConstraintUnsatisfied(
                    format!("Age {} is less than threshold {}", age, threshold)
                ));
            }
        }
    }
    
    let domain_element = get_commitment_domain();
    
    let circuit = SelectiveDisclosureCircuit {
        attributes: attributes.map(Some),
        mask: config.mask,
        blinding: Some(blinding),
        expected_commitment: Some(commitment),
        age_threshold: config.age_threshold.map(Fr::from),
        age_index: config.age_index.unwrap_or(0),
        domain_element,
    };

    let mut rng = ark_std::rand::thread_rng();
    
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        Groth16::<Bn254>::prove(&setup.proving_key, circuit, &mut rng)
    }));
    
    match result {
        Ok(Ok(proof)) => Ok(proof),
        Ok(Err(e)) => Err(CredentialError::ProofGenerationFailed(e.to_string())),
        Err(_) => Err(CredentialError::ConstraintUnsatisfied(
            "Constraint not satisfied (this usually means age < threshold)".into()
        )),
    }
}

/// Verify a zero-knowledge proof
pub fn verify_proof(
    setup: &TrustedSetup,
    proof: &ark_groth16::Proof<Bn254>,
    revealed_attributes: &[Option<Fr>; NUM_ATTRIBUTES],
    commitment: Fr,
    age_threshold: Option<u64>,
) -> std::result::Result<bool, CredentialError> {
    let mut public_inputs = Vec::with_capacity(NUM_ATTRIBUTES + 2);
    
    for i in 0..NUM_ATTRIBUTES {
        public_inputs.push(revealed_attributes[i].unwrap_or(Fr::zero()));
    }
    public_inputs.push(commitment);
    public_inputs.push(age_threshold.map(Fr::from).unwrap_or(Fr::zero()));

    Groth16::<Bn254>::verify(&setup.verifying_key, &public_inputs, proof)
        .map_err(|e| CredentialError::VerificationFailed(e.to_string()))
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Serialization helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/// Serialize proof to bytes
pub fn proof_to_bytes(proof: &ark_groth16::Proof<Bn254>) -> std::result::Result<Vec<u8>, CredentialError> {
    let mut bytes = Vec::new();
    proof.serialize_compressed(&mut bytes)
        .map_err(|e| CredentialError::SerializationError(e.to_string()))?;
    Ok(bytes)
}

/// Deserialize proof from bytes
pub fn proof_from_bytes(bytes: &[u8]) -> std::result::Result<ark_groth16::Proof<Bn254>, CredentialError> {
    ark_groth16::Proof::<Bn254>::deserialize_compressed(bytes)
        .map_err(|e| CredentialError::SerializationError(e.to_string()))
}

/// Convert Fr to string for display/serialization
pub fn fr_to_string(value: &Fr) -> String {
    value.to_string()
}

/// Parse Fr from string
pub fn fr_from_string(s: &str) -> std::result::Result<Fr, CredentialError> {
    use std::str::FromStr;
    Fr::from_str(s).map_err(|_| CredentialError::SerializationError("Invalid Fr string".into()))
}