#[derive(Debug)]
pub enum Rv {
    Ok,
    CryptokiNotInitialised,
    CryptokiAlreadyInitialised,
}

pub type Result<T> = core::result::Result<T, Rv>;
