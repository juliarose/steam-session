#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum SessionPersistence {
    Invalid = -1,
    Ephemeral = 0,
    Persistent = 1,
}