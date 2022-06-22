extern crate chromaprint_sys;
extern crate thiserror;

use chromaprint_sys::*;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("operation failed")]
    OperationFailed,
    #[error("invalid fingerprint string")]
    InvalidFingerprintString(#[from] std::str::Utf8Error),
    #[error("invalid argument: `{0}`")]
    InvalidArgument(String),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Algorithm {
    Test1 = 0,
    Test2,
    Test3,
    /// Removes leading silence.
    Test4,
    Test5,
}

impl Default for Algorithm {
    fn default() -> Self {
        Self::Test2
    }
}

#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Channels {
    One = 1,
    Two = 2,
}

#[derive(Debug)]
pub struct Fingerprint<F: FingerprintType> {
    inner: F,
}

pub trait FingerprintType {
    // Hacky way to circumvent this: https://doc.rust-lang.org/error-index.html#E0366
    fn drop(&mut self) {}
}

#[derive(Debug)]
pub struct Base64<'a>(&'a str);
#[derive(Debug)]
pub struct Raw<'a>(&'a [u32]);
#[derive(Debug)]
pub struct Hash(u32);

impl<'a> FingerprintType for Base64<'a> {
    fn drop(&mut self) {
        unsafe { chromaprint_dealloc(self.0.as_ptr() as *mut std::ffi::c_void) };
    }
}

impl<'a> FingerprintType for Raw<'a> {
    fn drop(&mut self) {
        unsafe { chromaprint_dealloc(self.0.as_ptr() as *mut std::ffi::c_void) };
    }
}

impl FingerprintType for Hash {}

impl<'a> Fingerprint<Base64<'a>> {
    pub fn get(&self) -> &'a str {
        self.inner.0
    }
}

impl<'a> Fingerprint<Raw<'a>> {
    pub fn get(&self) -> &'a [u32] {
        self.inner.0
    }
}

impl Fingerprint<Hash> {
    pub fn get(&self) -> u32 {
        self.inner.0
    }
}

impl<'a> TryFrom<Fingerprint<Raw<'a>>> for Fingerprint<Hash> {
    type Error = Error;
    fn try_from(raw: Fingerprint<Raw<'a>>) -> Result<Self> {
        let mut hash: u32 = 0;
        let data = raw.get();
        let rc =
            unsafe { chromaprint_hash_fingerprint(data.as_ptr(), data.len() as i32, &mut hash) };
        if rc != 1 {
            return Err(Error::OperationFailed);
        }
        return Ok(Fingerprint { inner: Hash(hash) });
    }
}

impl<F: FingerprintType> Drop for Fingerprint<F> {
    fn drop(&mut self) {
        self.inner.drop();
    }
}

pub struct Context {
    ctx: *mut ChromaprintContext,
    algorithm: Algorithm,
}

impl Context {
    pub fn new(algorithm: Algorithm) -> Self {
        let ctx = unsafe { chromaprint_new(algorithm as i32) };
        Self { ctx, algorithm }
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    pub fn start(&mut self, sample_rate: u32, num_channels: Channels) -> Result<()> {
        let sample_rate = sample_rate as i32;
        let num_channels = num_channels as i32;
        let rc = unsafe { chromaprint_start(self.ctx, sample_rate, num_channels) };
        if rc != 1 {
            return Err(Error::OperationFailed);
        }
        Ok(())
    }

    pub fn feed(&mut self, data: &[i16]) -> Result<()> {
        let rc = unsafe { chromaprint_feed(self.ctx, data.as_ptr(), data.len() as i32) };
        if rc != 1 {
            return Err(Error::OperationFailed);
        }
        Ok(())
    }

    pub fn finish(&mut self) -> Result<()> {
        let rc = unsafe { chromaprint_finish(self.ctx) };
        if rc != 1 {
            return Err(Error::OperationFailed);
        }
        Ok(())
    }

    pub fn get_fingerprint_base64<'a>(&'a mut self) -> Result<Fingerprint<Base64>> {
        let mut out_ptr = std::ptr::null::<*const libc::c_char>() as *mut libc::c_char;
        let rc = unsafe { chromaprint_get_fingerprint(self.ctx, std::ptr::addr_of_mut!(out_ptr)) };
        if rc != 1 {
            return Err(Error::OperationFailed);
        }
        let s = unsafe { std::ffi::CStr::from_ptr(out_ptr as *const libc::c_char) }.to_str();
        if s.is_err() {
            return Err(Error::InvalidFingerprintString(s.err().unwrap()));
        }
        Ok(Fingerprint {
            inner: Base64(s.unwrap()),
        })
    }

    pub fn get_fingerprint_raw<'a>(&'a mut self) -> Result<Fingerprint<Raw>> {
        let mut data_ptr = std::ptr::null::<*const u32>() as *mut u32;
        let mut size: i32 = 0;
        let rc = unsafe { chromaprint_get_raw_fingerprint(self.ctx, &mut data_ptr, &mut size) };
        if rc != 1 {
            return Err(Error::OperationFailed);
        }
        let s = unsafe { std::slice::from_raw_parts_mut(data_ptr, size as usize) };
        Ok(Fingerprint { inner: Raw(s) })
    }

    pub fn get_fingerprint_hash(&mut self) -> Result<Fingerprint<Hash>> {
        let mut hash: u32 = 0;
        let rc = unsafe { chromaprint_get_fingerprint_hash(self.ctx, &mut hash) };
        if rc != 1 {
            return Err(Error::OperationFailed);
        }
        Ok(Fingerprint { inner: Hash(hash) })
    }

    pub fn clear_fingerprint(&mut self) -> Result<()> {
        let rc = unsafe { chromaprint_clear_fingerprint(self.ctx) };
        if rc != 1 {
            return Err(Error::OperationFailed);
        }
        Ok(())
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new(Algorithm::default())
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { chromaprint_free(self.ctx) }
    }
}
