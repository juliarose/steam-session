#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AuthSessionSecurityHistory {
    Invalid = 0,
    UsedPreviously = 1,
    NoPriorHistory = 2,
}
