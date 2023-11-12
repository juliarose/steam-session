#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AuthTokenPlatformType {
    Unknown = 0,
    SteamClient = 1,
    WebBrowser = 2,
    MobileApp = 3,
}