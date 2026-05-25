use ark_bn254::{Bn254, Fr};
use ark_ff::{Field, Zero, PrimeField};
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::*;
use ark_snark::SNARK;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

use crate::error::CredentialError;
use crate::types::*;

pub const NUM_ATTRIBUTES: usize = 16;
pub const PUBLIC_INPUT_SIZE: usize = NUM_ATTRIBUTES + 3;
pub const FULL_ROUNDS: usize = 8;
pub const PARTIAL_ROUNDS: usize = 56;
pub const TOTAL_ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;
pub const STATE_WIDTH: usize = 3;
pub const RATE: usize = 2;
pub const MAX_WINDOW_SECONDS: u64 = 300;

const DOMAIN_SEP: &[u8] = b"DataIntegrityGroth16Proof2026::";
const COMMITMENT_DOMAIN: &[u8] = b"Commitment";
const ATTRIBUTE_HASH_DOMAIN: &[u8] = b"AttributeHash";
const BLINDING_DERIVATION: &[u8] = b"BlindingDerivation";

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Poseidon Hash Parameters
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Poseidon Hash - Native
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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
    for i in 0..STATE_WIDTH { state[i] += rc[i]; }
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
    for i in 0..FULL_ROUNDS / 2 { full_round(state, i, params); }
    for i in 0..PARTIAL_ROUNDS { partial_round(state, FULL_ROUNDS / 2 + i, params); }
    for i in 0..FULL_ROUNDS / 2 { full_round(state, FULL_ROUNDS / 2 + PARTIAL_ROUNDS + i, params); }
}

pub fn poseidon_sponge_hash(inputs: &[Fr]) -> Fr {
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

pub fn hash_attribute(value: &str) -> Fr {
    let mut sha = Sha256::new();
    sha.update(DOMAIN_SEP);
    sha.update(ATTRIBUTE_HASH_DOMAIN);
    sha.update(value.as_bytes());
    Fr::from_be_bytes_mod_order(&sha.finalize())
}

pub fn create_commitment(attrs: &[Fr; NUM_ATTRIBUTES], blinding: &Fr) -> Fr {
    let mut inputs = Vec::with_capacity(NUM_ATTRIBUTES + 1);
    inputs.extend_from_slice(attrs);
    inputs.push(*blinding);
    poseidon_hash(&inputs, COMMITMENT_DOMAIN)
}

pub fn derive_blinding(holder_secret: &[u8; 32], credential_nonce: &[u8; 32]) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN_SEP);
    hasher.update(BLINDING_DERIVATION);
    hasher.update(holder_secret);
    hasher.update(credential_nonce);
    Fr::from_be_bytes_mod_order(&hasher.finalize())
}

pub fn generate_holder_secret() -> [u8; 32] {
    let mut secret = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret);
    secret
}

pub fn generate_credential_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
    nonce
}

pub fn get_commitment_domain() -> Fr {
    let mut sha = Sha256::new();
    sha.update(DOMAIN_SEP);
    sha.update(COMMITMENT_DOMAIN);
    Fr::from_be_bytes_mod_order(&sha.finalize())
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Poseidon Circuit
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

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
    for i in 0..STATE_WIDTH { state[i] = &state[i] + FpVar::Constant(rc[i]); }
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

fn poseidon_permutation_circuit(state: &mut [FpVar<Fr>; STATE_WIDTH]) -> Result<(), SynthesisError> {
    let params = get_poseidon_params();
    for i in 0..FULL_ROUNDS / 2 { full_round_circuit(state, i, params)?; }
    for i in 0..PARTIAL_ROUNDS { partial_round_circuit(state, FULL_ROUNDS / 2 + i, params)?; }
    for i in 0..FULL_ROUNDS / 2 { full_round_circuit(state, FULL_ROUNDS / 2 + PARTIAL_ROUNDS + i, params)?; }
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

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Full Circuit with Fixed Predicate Matrix
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct MatrixCircuit {
    pub attributes: [Option<Fr>; NUM_ATTRIBUTES],
    pub mask: [bool; NUM_ATTRIBUTES],
    pub blinding: Option<Fr>,
    pub expected_commitment: Option<Fr>,
    pub predicates: [PredicateSlot; MAX_PREDICATES],
    pub window_start: Option<u32>,
    pub window_expires: Option<u32>,
    pub domain_element: Fr,
}

impl ConstraintSynthesizer<Fr> for MatrixCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let domain_var = FpVar::Constant(self.domain_element);

        // Public inputs: revealed attributes (zero for hidden)
        let mut public_attr_vars = Vec::with_capacity(NUM_ATTRIBUTES);
        for i in 0..NUM_ATTRIBUTES {
            let val = if self.mask[i] { self.attributes[i].unwrap_or_else(Fr::zero) } else { Fr::zero() };
            public_attr_vars.push(FpVar::new_input(cs.clone(), || Ok(val))?);
        }

        let expected_commitment_var = FpVar::new_input(cs.clone(), || {
            Ok(self.expected_commitment.unwrap_or_else(Fr::zero))
        })?;

        // Witnesses: all attributes (hidden or revealed) + blinding
        let mut attr_witnesses = Vec::with_capacity(NUM_ATTRIBUTES);
        for i in 0..NUM_ATTRIBUTES {
            let raw = self.attributes[i].unwrap_or_else(Fr::zero);
            let w = FpVar::new_witness(cs.clone(), || Ok(raw))?;
            if self.mask[i] { w.enforce_equal(&public_attr_vars[i])?; }
            attr_witnesses.push(w);
        }

        let blinding_var = FpVar::new_witness(cs.clone(), || {
            Ok(self.blinding.unwrap_or_else(Fr::zero))
        })?;

        // Constraint 1: Commitment check
        // EXACT order matching create_commitment: [domain, attr_0..attr_15, blinding]
        let mut hash_inputs = vec![domain_var];
        for w in &attr_witnesses { hash_inputs.push(w.clone()); }
        hash_inputs.push(blinding_var);
        poseidon_sponge_hash_circuit(&hash_inputs)?.enforce_equal(&expected_commitment_var)?;

        // Constraint 2: Timestamp window
        let ws = self.window_start.unwrap_or(0);
        let we = self.window_expires.unwrap_or(0);
        let ws_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(ws as u64)))?;
        let we_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(we as u64)))?;
        let ws_pub = FpVar::new_input(cs.clone(), || Ok(Fr::from(ws as u64)))?;
        let we_pub = FpVar::new_input(cs.clone(), || Ok(Fr::from(we as u64)))?;
        ws_var.enforce_equal(&ws_pub)?;
        we_var.enforce_equal(&we_pub)?;

        let delta = &we_var - &ws_var;
        let delta_bits = delta.to_bits_le()?;
        for bit in delta_bits.iter().skip(32) { bit.enforce_equal(&Boolean::constant(false))?; }
        let is_zero = delta_bits.iter().take(32).fold(Boolean::constant(true), |acc, b| {
            Boolean::and(&acc, &b.not()).unwrap()
        });
        is_zero.enforce_equal(&Boolean::constant(false))?;

        // Constraint 3: Predicate matrix (all MAX_PREDICATES slots)
        for slot_idx in 0..MAX_PREDICATES {
            let slot = &self.predicates[slot_idx];
            if !slot.active { continue; }
            let attr = &attr_witnesses[slot.attr_index];

            match slot.pred_type {
                1 | 9 | 10 | 11 => {
                    let d = FpVar::new_witness(cs.clone(), || {
                        let a = fr_to_u64(&self.attributes[slot.attr_index].unwrap_or_else(Fr::zero));
                        let t = fr_to_u64(&slot.val1);
                        Ok(if a >= t { u64_to_fr(a - t) } else { Fr::zero() })
                    })?;
                    let r = &FpVar::Constant(slot.val1) + &d;
                    (attr - &r).enforce_equal(&FpVar::zero())?;
                    for bit in d.to_bits_le()?.iter().skip(32) { bit.enforce_equal(&Boolean::constant(false))?; }
                }
                2 => {
                    let gt_t = slot.val1 + Fr::from(1u64);
                    let d = FpVar::new_witness(cs.clone(), || {
                        let a = fr_to_u64(&self.attributes[slot.attr_index].unwrap_or_else(Fr::zero));
                        Ok(if a >= fr_to_u64(&gt_t) { u64_to_fr(a - fr_to_u64(&gt_t)) } else { Fr::zero() })
                    })?;
                    (attr - &(&FpVar::Constant(gt_t) + &d)).enforce_equal(&FpVar::zero())?;
                    for bit in d.to_bits_le()?.iter().skip(32) { bit.enforce_equal(&Boolean::constant(false))?; }
                }
                3 => {
                    let lt_b = slot.val1 - Fr::from(1u64);
                    let d = FpVar::new_witness(cs.clone(), || {
                        let a = fr_to_u64(&self.attributes[slot.attr_index].unwrap_or_else(Fr::zero));
                        Ok(if fr_to_u64(&lt_b) >= a { u64_to_fr(fr_to_u64(&lt_b) - a) } else { Fr::zero() })
                    })?;
                    (&FpVar::Constant(lt_b) - &(attr + &d)).enforce_equal(&FpVar::zero())?;
                    for bit in d.to_bits_le()?.iter().skip(32) { bit.enforce_equal(&Boolean::constant(false))?; }
                }
                4 => {
                    let d = FpVar::new_witness(cs.clone(), || {
                        let a = fr_to_u64(&self.attributes[slot.attr_index].unwrap_or_else(Fr::zero));
                        Ok(if fr_to_u64(&slot.val1) >= a { u64_to_fr(fr_to_u64(&slot.val1) - a) } else { Fr::zero() })
                    })?;
                    (&FpVar::Constant(slot.val1) - &(attr + &d)).enforce_equal(&FpVar::zero())?;
                    for bit in d.to_bits_le()?.iter().skip(32) { bit.enforce_equal(&Boolean::constant(false))?; }
                }
                5 => {
                    (attr - &FpVar::Constant(slot.val1)).enforce_equal(&FpVar::zero())?;
                }
                6 => {
                    let diff = attr - &FpVar::Constant(slot.val1);
                    let inv = FpVar::new_witness(cs.clone(), || {
                        let a = self.attributes[slot.attr_index].unwrap_or_else(Fr::zero);
                        if a != slot.val1 { Ok((a - slot.val1).inverse().unwrap_or(Fr::from(1u64))) } else { Ok(Fr::from(1u64)) }
                    })?;
                    (&diff * &inv).enforce_equal(&FpVar::Constant(Fr::from(1u64)))?;
                }
                7 => {
                    let d1 = FpVar::new_witness(cs.clone(), || {
                        let a = fr_to_u64(&self.attributes[slot.attr_index].unwrap_or_else(Fr::zero));
                        Ok(if a >= fr_to_u64(&slot.val1) { u64_to_fr(a - fr_to_u64(&slot.val1)) } else { Fr::zero() })
                    })?;
                    let d2 = FpVar::new_witness(cs.clone(), || {
                        let a = fr_to_u64(&self.attributes[slot.attr_index].unwrap_or_else(Fr::zero));
                        Ok(if fr_to_u64(&slot.val2) >= a { u64_to_fr(fr_to_u64(&slot.val2) - a) } else { Fr::zero() })
                    })?;
                    (attr - &(&FpVar::Constant(slot.val1) + &d1)).enforce_equal(&FpVar::zero())?;
                    (&FpVar::Constant(slot.val2) - &(attr + &d2)).enforce_equal(&FpVar::zero())?;
                    for d in &[d1, d2] {
                        for bit in d.to_bits_le()?.iter().skip(32) { bit.enforce_equal(&Boolean::constant(false))?; }
                    }
                }
                8 => {
                    let mut product = FpVar::Constant(Fr::from(1u64));
                    for vi in 0..MAX_INSET_VALUES {
                        product = &product * &(attr - &FpVar::Constant(slot.inset_values[vi]));
                    }
                    product.enforce_equal(&FpVar::zero())?;
                }
                _ => {}
            }
        }

        Ok(())
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Key Management
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub struct TrustedSetup {
    pub proving_key: ark_groth16::ProvingKey<Bn254>,
    pub verifying_key: ark_groth16::VerifyingKey<Bn254>,
}

impl TrustedSetup {
    pub fn new() -> Result<Self, CredentialError> {
        let domain_element = get_commitment_domain();
        
        let zero_attrs = [Some(Fr::zero()); NUM_ATTRIBUTES];
        let blinding = Fr::zero();
        let blank_commitment = create_commitment(&[Fr::zero(); NUM_ATTRIBUTES], &blinding);

        let mut predicates = [PredicateSlot::default(); MAX_PREDICATES];
        for i in 0..MAX_PREDICATES {
            predicates[i] = PredicateSlot {
                active: true,
                pred_type: 5,
                attr_index: 0,
                val1: Fr::zero(),
                val2: Fr::zero(),
                inset_values: [Fr::zero(); MAX_INSET_VALUES],
                inset_count: 0,
            };
        }
        
        let blank = MatrixCircuit {
            attributes: zero_attrs,
            mask: [false; NUM_ATTRIBUTES],
            blinding: Some(blinding),
            expected_commitment: Some(blank_commitment),
            predicates,
            window_start: Some(0),
            window_expires: Some(1),
            domain_element,
        };

        let mut rng = ark_std::rand::thread_rng();
        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(blank, &mut rng)
            .map_err(|e| CredentialError::SetupFailed(e.to_string()))?;

        Ok(Self { proving_key: pk, verifying_key: vk })
    }

    pub fn save(&self, dir: &std::path::Path) -> Result<(), CredentialError> {
        std::fs::create_dir_all(dir)?;
        let mut pk_bytes = Vec::new();
        self.proving_key.serialize_compressed(&mut pk_bytes)
            .map_err(|e| CredentialError::SerializationError(e.to_string()))?;
        std::fs::write(dir.join("proving_key.bin"), &pk_bytes)?;
        let mut vk_bytes = Vec::new();
        self.verifying_key.serialize_compressed(&mut vk_bytes)
            .map_err(|e| CredentialError::SerializationError(e.to_string()))?;
        std::fs::write(dir.join("verifying_key.bin"), &vk_bytes)?;
        Ok(())
    }

    pub fn load(dir: &std::path::Path) -> Result<Self, CredentialError> {
        let pk_bytes = std::fs::read(dir.join("proving_key.bin"))?;
        let vk_bytes = std::fs::read(dir.join("verifying_key.bin"))?;
        let pk = ark_groth16::ProvingKey::<Bn254>::deserialize_compressed(&pk_bytes[..])
            .map_err(|e| CredentialError::SerializationError(e.to_string()))?;
        let vk = ark_groth16::VerifyingKey::<Bn254>::deserialize_compressed(&vk_bytes[..])
            .map_err(|e| CredentialError::SerializationError(e.to_string()))?;
        Ok(Self { proving_key: pk, verifying_key: vk })
    }
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// Proof Generation & Verification
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pub fn generate_proof(
    setup: &TrustedSetup,
    attributes: &[Fr; NUM_ATTRIBUTES],
    blinding: Fr,
    commitment: Fr,
    predicates: &[PredicateSlot; MAX_PREDICATES],
    mask: &[bool; NUM_ATTRIBUTES],
    window_start: u32,
    window_expires: u32,
) -> Result<Vec<u8>, CredentialError> {
    let domain_element = get_commitment_domain();
    
    let circuit = MatrixCircuit {
        attributes: attributes.map(Some),
        mask: *mask,
        blinding: Some(blinding),
        expected_commitment: Some(commitment),
        predicates: *predicates,
        window_start: Some(window_start),
        window_expires: Some(window_expires),
        domain_element,
    };

    let mut rng = ark_std::rand::thread_rng();
    let proof = Groth16::<Bn254>::prove(&setup.proving_key, circuit, &mut rng)
        .map_err(|e| CredentialError::ProofGenerationFailed(e.to_string()))?;

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)
        .map_err(|e| CredentialError::SerializationError(e.to_string()))?;
    Ok(proof_bytes)
}

pub fn verify_proof(
    setup: &TrustedSetup,
    proof_bytes: &[u8],
    public_inputs: &[Fr; PUBLIC_INPUT_SIZE],
) -> Result<bool, CredentialError> {
    let proof = ark_groth16::Proof::<Bn254>::deserialize_compressed(proof_bytes)
        .map_err(|e| CredentialError::SerializationError(e.to_string()))?;
    Groth16::<Bn254>::verify(&setup.verifying_key, public_inputs, &proof)
        .map_err(|e| CredentialError::VerificationFailed(e.to_string()))
}

pub fn derive_nonce(credential_id: &str, holder_secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"CredentialNonce");
    hasher.update(credential_id.as_bytes());
    hasher.update(holder_secret);
    let result = hasher.finalize();
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&result);
    nonce
}