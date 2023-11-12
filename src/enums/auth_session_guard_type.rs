#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AuthSessionGuardType {
    Unknown = 0,
    None = 1,
    EmailCode = 2,
    DeviceCode = 3,
    DeviceConfirmation = 4,
    EmailConfirmation = 5,
    MachineToken = 6,
    LegacyMachineAuth = 7,
}