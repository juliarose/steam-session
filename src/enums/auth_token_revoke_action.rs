#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AuthTokenRevokeAction {
    Logout = 0,
    Permanent = 1,
    Replaced = 2,
    Support = 3,
    Consume = 4,
    NonRememberedLogout = 5,
    NonRememberedPermanent = 6,
    Automatic = 7,
}
