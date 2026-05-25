use std::collections::VecDeque;
use std::sync::{Arc, RwLock, atomic::{AtomicBool, Ordering}};
use std::sync::mpsc::channel;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::suite::PoseidonGroth16Suite;
use crate::types::*;

const PROOF_WINDOW_SECONDS: u64 = 30;
const CACHE_SIZE: usize = 4;

#[derive(Clone)]
pub struct CachedProof {
    pub credential: VerifiableCredential,
    pub proof_bytes: Vec<u8>,
}

pub struct ProofCache {
    proofs: Arc<RwLock<VecDeque<CachedProof>>>,
    running: Arc<AtomicBool>,
    _worker: Option<thread::JoinHandle<()>>,
}

impl ProofCache {
    pub fn new(
        suite: Arc<PoseidonGroth16Suite>,
        credential: VerifiableCredential,
        reveal: RevealRequest,
        predicates: Vec<PredicateType>,
    ) -> Self {
        let proofs: Arc<RwLock<VecDeque<CachedProof>>> = Arc::new(RwLock::new(VecDeque::with_capacity(CACHE_SIZE)));
        let running = Arc::new(AtomicBool::new(true));
        let (tx, rx) = channel::<CachedProof>();

        let proofs_clone = proofs.clone();
        let mgr = running.clone();
        thread::spawn(move || {
            while mgr.load(Ordering::Relaxed) {
                if let Ok(cp) = rx.recv_timeout(Duration::from_millis(200)) {
                    let mut lock = proofs_clone.write().unwrap();
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                    lock.retain(|p| p.credential.window_expires > now);
                    lock.push_back(cp);
                    if lock.len() > CACHE_SIZE { lock.pop_front(); }
                }
            }
        });

        let worker_running = running.clone();
        let worker = thread::spawn(move || {
            let mut next = Self::current_window_start();
            while worker_running.load(Ordering::SeqCst) {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
                if next > now + (PROOF_WINDOW_SECONDS * CACHE_SIZE as u64) {
                    thread::sleep(Duration::from_millis(500));
                    continue;
                }
                let ws = next; let we = ws + PROOF_WINDOW_SECONDS;
                if let Ok(vc) = suite.derive_proof_with_timestamp(&credential, &reveal, &predicates, ws, we) {
                    let pb = base64_url::decode(&vc.proof_value).unwrap_or_default();
                    let _ = tx.send(CachedProof { credential: vc, proof_bytes: pb });
                }
                next += PROOF_WINDOW_SECONDS;
            }
        });

        ProofCache { proofs, running, _worker: Some(worker) }
    }

    fn current_window_start() -> u64 {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        now - (now % PROOF_WINDOW_SECONDS)
    }

    pub fn get_proof(&self) -> Option<CachedProof> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let lock = self.proofs.read().unwrap();
        lock.iter().find(|p| now >= p.credential.window_start && now < p.credential.window_expires).cloned()
    }

    pub fn stop(&mut self) { self.running.store(false, Ordering::SeqCst); }
}