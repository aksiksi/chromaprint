extern crate chromaprint_sys;
extern crate thiserror;

use std::ffi::{c_void, CStr};

use chromaprint_sys::*;
use thiserror::Error;

#[derive(Error, Debug)]
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
pub enum Fingerprint<'a> {
    Base64(&'a str),
    Raw(&'a [u32]),
    Hash(u32),
}

impl<'a> Fingerprint<'a> {
    #[inline]
    pub fn base64(&self) -> Option<&'a str> {
        match *self {
            Fingerprint::Base64(v) => Some(v),
            _ => None,
        }
    }

    #[inline]
    pub fn raw(&self) -> Option<&'a [u32]> {
        match *self {
            Fingerprint::Raw(v) => Some(v),
            _ => None,
        }
    }

    #[inline]
    pub fn hash(&self) -> Option<u32> {
        match *self {
            Fingerprint::Hash(v) => Some(v),
            _ => None,
        }
    }

    /// Convert a raw fingerprint to a hash.
    ///
    /// If this method is called on a non-raw fingerprint, an `InvalidArgument` error will be returned.
    pub fn to_hash(&self) -> Result<Fingerprint<'_>> {
        if let Some(raw) = self.raw() {
            let mut hash: u32 = 0;
            let rc =
                unsafe { chromaprint_hash_fingerprint(raw.as_ptr(), raw.len() as i32, &mut hash) };
            if rc != 1 {
                return Err(Error::OperationFailed);
            }
            return Ok(Self::Hash(hash));
        }

        Err(Error::InvalidArgument(
            "raw fingerprint required".to_string(),
        ))
    }
}

impl<'a> Drop for Fingerprint<'a> {
    fn drop(&mut self) {
        let mut ptr: Option<*mut c_void> = None;
        match self {
            Fingerprint::Base64(s) => ptr = Some(s.as_ptr() as *mut c_void),
            Fingerprint::Raw(s) => ptr = Some(s.as_ptr() as *mut c_void),
            Fingerprint::Hash(_) => (),
        }
        if let Some(ptr) = ptr {
            unsafe { chromaprint_dealloc(ptr) };
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum FingerprintKind {
    Base64,
    Raw,
    Hash,
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

    pub fn get_fingerprint<'a>(&'a mut self, kind: FingerprintKind) -> Result<Fingerprint<'_>> {
        let fingerprint: Fingerprint;
        match kind {
            FingerprintKind::Base64 => {
                let mut out_ptr = std::ptr::null::<*const libc::c_char>() as *mut libc::c_char;
                let rc = unsafe {
                    chromaprint_get_fingerprint(self.ctx, std::ptr::addr_of_mut!(out_ptr))
                };
                if rc != 1 {
                    return Err(Error::OperationFailed);
                }
                let s = unsafe { CStr::from_ptr(out_ptr as *const libc::c_char) }.to_str();
                if s.is_err() {
                    return Err(Error::InvalidFingerprintString(s.err().unwrap()));
                }
                fingerprint = Fingerprint::Base64(s.unwrap());
            }
            FingerprintKind::Raw => {
                let mut data_ptr = std::ptr::null::<*const u32>() as *mut u32;
                let mut size: i32 = 0;
                let rc =
                    unsafe { chromaprint_get_raw_fingerprint(self.ctx, &mut data_ptr, &mut size) };
                if rc != 1 {
                    return Err(Error::OperationFailed);
                }
                let s = unsafe { std::slice::from_raw_parts_mut(data_ptr, size as usize) };
                fingerprint = Fingerprint::Raw(s);
            }
            FingerprintKind::Hash => {
                let mut hash: u32 = 0;
                let rc = unsafe { chromaprint_get_fingerprint_hash(self.ctx, &mut hash) };
                if rc != 1 {
                    return Err(Error::OperationFailed);
                }
                fingerprint = Fingerprint::Hash(hash);
            }
        }
        Ok(fingerprint)
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
        let algorithm = Algorithm::default();
        let ctx = unsafe { chromaprint_new(algorithm as i32) };
        Self { ctx, algorithm }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe { chromaprint_free(self.ctx) }
    }
}
