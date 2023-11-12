#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BanContentCheckResult {
    NotScanned = 0,
    Reset = 1,
    NeedsChecking = 2,
    VeryUnlikely = 5,
    Unlikely = 30,
    Possible = 50,
    Likely = 75,
    VeryLikely = 100
}