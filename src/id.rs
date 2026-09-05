use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::LazyLock;

use uuid::Uuid;

static CLIENT_ID_GEN: LazyLock<IdGenerator> = LazyLock::new(IdGenerator::new);

pub fn next_client_id() -> usize {
    CLIENT_ID_GEN.next()
}

pub fn next_request_id() -> String {
    Uuid::new_v4().to_string()
}

#[derive(Debug)]
struct IdGenerator {
    last_id: AtomicUsize,
}

impl IdGenerator {
    const fn new() -> Self {
        IdGenerator {
            last_id: AtomicUsize::new(0),
        }
    }

    fn next(&self) -> usize {
        self.last_id.fetch_add(1, Ordering::Relaxed) + 1
    }
}
