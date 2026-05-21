use ark_bn254::{Bn254, Fr};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::prelude::*;
use ark_snark::SNARK;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use std::time::Instant;
use ark_r1cs_std::fields::fp::FpVar;

// =============================================================================
// Domain separation
// =============================================================================
const DOMAIN_SEP: &[u8] = b"DataIntegrityGroth16Proof2026::v1.0::";
const COMMITMENT_DOMAIN: &[u8] = b"Commitment";
const ATTRIBUTE_HASH_DOMAIN: &[u8] = b"AttributeHash";

// =============================================================================
// Poseidon parameters (native — same as Parts 1-2)
// =============================================================================
const FULL_ROUNDS: usize = 8;
const PARTIAL_ROUNDS: usize = 56;
const TOTAL_ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;
const STATE_WIDTH: usize = 3;
const RATE: usize = 2;

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

// =============================================================================
// Native Poseidon (Parts 1-2)
// =============================================================================
fn sbox(x: &Fr) -> Fr {
    let x2 = x.square();
    let x4 = x2.square();
    *x * x4
}

fn full_round(state: &mut [Fr; STATE_WIDTH], round_idx: usize, params: &PoseidonParams) {
    let rc = &params.constants[round_idx];
    for i in 0..STATE_WIDTH { state[i] += rc[i]; }
    for i in 0..STATE_WIDTH { state[i] = sbox(&state[i]); }
    let old = *state;
    for i in 0..STATE_WIDTH {
        state[i] = Fr::zero();
        for j in 0..STATE_WIDTH { state[i] += params.mds[i][j] * old[j]; }
    }
}

fn partial_round(state: &mut [Fr; STATE_WIDTH], round_idx: usize, params: &PoseidonParams) {
    let rc = &params.constants[round_idx];
    for i in 0..STATE_WIDTH { state[i] += rc[i]; }
    state[0] = sbox(&state[0]);
    let old = *state;
    for i in 0..STATE_WIDTH {
        state[i] = Fr::zero();
        for j in 0..STATE_WIDTH { state[i] += params.mds[i][j] * old[j]; }
    }
}

fn poseidon_permutation(state: &mut [Fr; STATE_WIDTH]) {
    let params = get_params();
    for i in 0..FULL_ROUNDS / 2 { full_round(state, i, params); }
    for i in 0..PARTIAL_ROUNDS { partial_round(state, FULL_ROUNDS / 2 + i, params); }
    for i in 0..FULL_ROUNDS / 2 { full_round(state, FULL_ROUNDS / 2 + PARTIAL_ROUNDS + i, params); }
}

fn poseidon_sponge_hash(inputs: &[Fr]) -> Fr {
    let mut state = [Fr::zero(); STATE_WIDTH];
    let mut i = 0;
    while i < inputs.len() {
        for j in 0..RATE {
            if i < inputs.len() { state[j] += inputs[i]; i += 1; }
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

fn create_commitment(attrs: &[Fr; 16], blinding: &Fr) -> Fr {
    let mut inputs = Vec::with_capacity(17);
    inputs.extend_from_slice(attrs);
    inputs.push(*blinding);
    poseidon_hash(&inputs, COMMITMENT_DOMAIN)
}

fn random_fr() -> Fr {
    let mut bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    Fr::from_le_bytes_mod_order(&bytes)
}

// =============================================================================
// PART 3: Circuit S-box (x^5) in R1CS
// =============================================================================
fn sbox_circuit(x: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let x2 = x.square()?;
    let x4 = x2.square()?;
    Ok(&x4 * x) // x^4 * x = x^5
}

// =============================================================================
// PART 3: Circuit — Full Round
// =============================================================================
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

// =============================================================================
// PART 3: Circuit — Partial Round
// =============================================================================
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

// =============================================================================
// PART 3: Circuit — Poseidon Permutation
// =============================================================================
fn poseidon_permutation_circuit(
    state: &mut [FpVar<Fr>; STATE_WIDTH],
) -> Result<(), SynthesisError> {
    let params = get_params();
    for i in 0..FULL_ROUNDS / 2 { full_round_circuit(state, i, params)?; }
    for i in 0..PARTIAL_ROUNDS { partial_round_circuit(state, FULL_ROUNDS / 2 + i, params)?; }
    for i in 0..FULL_ROUNDS / 2 { full_round_circuit(state, FULL_ROUNDS / 2 + PARTIAL_ROUNDS + i, params)?; }
    Ok(())
}

// =============================================================================
// PART 3: Circuit — Sponge Hash
// =============================================================================
fn poseidon_sponge_hash_circuit(
    inputs: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
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

// =============================================================================
// PART 3: The Circuit Definition
// =============================================================================
struct DataIntegrityCircuit {
    // Private witnesses: 16 attributes + blinding
    pub attributes: Vec<Option<Fr>>,
    pub blinding: Option<Fr>,
    
    // Public input: the commitment we're proving knowledge of
    pub expected_commitment: Option<Fr>,
    
    // Domain element (computed from domain tag)
    pub domain_element: Fr,
}

impl ConstraintSynthesizer<Fr> for DataIntegrityCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // 1. Allocate domain element as constant
        let domain_var = FpVar::Constant(self.domain_element);

        // 2. Allocate private witnesses (16 attributes)
        let mut input_vars: Vec<FpVar<Fr>> = vec![domain_var];
        for attr in self.attributes {
            input_vars.push(FpVar::new_witness(
                cs.clone(),
                || attr.ok_or(SynthesisError::AssignmentMissing),
            )?);
        }

        // 3. Allocate blinding factor
        let blinding_var = FpVar::new_witness(
            cs.clone(),
            || self.blinding.ok_or(SynthesisError::AssignmentMissing),
        )?;
        input_vars.push(blinding_var);

        // 4. Allocate public input: expected commitment
        let expected_commitment_var = FpVar::new_input(
            cs.clone(),
            || self.expected_commitment.ok_or(SynthesisError::AssignmentMissing),
        )?;

        // 5. Compute Poseidon hash INSIDE the circuit
        let computed_commitment = poseidon_sponge_hash_circuit(&input_vars)?;

        // 6. Enforce: computed == expected
        computed_commitment.enforce_equal(&expected_commitment_var)?;

        Ok(())
    }
}

// =============================================================================
// Main
// =============================================================================
fn main() {
    println!("╔══════════════════════════════════════════════════════════╗");
    println!("║  DataIntegrityGroth16Proof2026 — Parts 1-3               ║");
    println!("╚══════════════════════════════════════════════════════════╝\n");

    // ── Parts 1-2: Native Poseidon ────────────────────────────────────────
    println!("━━━ PARTS 1-2: NATIVE POSEIDON ━━━\n");

    let alice   = hash_attribute("Alice");
    let age     = hash_attribute("25");
    let over18  = hash_attribute("true");
    let address = hash_attribute("123 Main St");

    let mut attrs = [Fr::zero(); 16];
    attrs[0] = alice; attrs[1] = age; attrs[2] = over18; attrs[3] = address;

    let blinding   = random_fr();
    let commitment = create_commitment(&attrs, &blinding);

    println!("Native commitment: {}", commitment);

    // ── Part 3: Groth16 Proof ─────────────────────────────────────────────
    println!("\n━━━ PART 3: GROTH16 ZERO-KNOWLEDGE PROOF ━━━\n");

    // Domain element (same as native)
    let mut sha = Sha256::new();
    sha.update(DOMAIN_SEP);
    sha.update(COMMITMENT_DOMAIN);
    let domain_element = Fr::from_be_bytes_mod_order(&sha.finalize());

    // Circuit with real witness values
    let circuit = DataIntegrityCircuit {
        attributes: attrs.iter().map(|&x| Some(x)).collect(),
        blinding: Some(blinding),
        expected_commitment: Some(commitment),
        domain_element,
    };

    // Trusted setup
    let mut rng = ark_std::rand::thread_rng();
    println!("Running trusted setup...");
    let t = Instant::now();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
        DataIntegrityCircuit {
            attributes: vec![None; 16],
            blinding: None,
            expected_commitment: None,
            domain_element,
        },
        &mut rng,
    ).expect("Setup failed");
    println!("  Setup: {:?}", t.elapsed());

    // Generate proof
    println!("Generating proof...");
    let t = Instant::now();
    let proof = Groth16::<Bn254>::prove(&pk, circuit, &mut rng)
        .expect("Proof generation failed");
    println!("  Prove: {:?}", t.elapsed());

    // Verify proof
    println!("Verifying proof...");
    let t = Instant::now();
    let public_inputs = vec![commitment];
    let is_valid = Groth16::<Bn254>::verify(&vk, &public_inputs, &proof)
        .expect("Verification error");
    println!("  Verify: {:?}", t.elapsed());

    if is_valid {
        println!("\n✓ ZK Proof VALID — holder knows attributes matching commitment");
    } else {
        println!("\n✗ ZK Proof INVALID");
    }

    // ── Verify zero-knowledge property ──
    println!("\n━━━ ZERO-KNOWLEDGE DEMONSTRATION ━━━\n");
    println!("  Verifier sees: commitment = {}", commitment);
    println!("  Verifier learns: NOTHING about the 16 attributes");
    println!("  Verifier learns: NOTHING about the blinding factor");
    println!("  Only check: Poseidon(attrs, blinding) == commitment ✓");
}