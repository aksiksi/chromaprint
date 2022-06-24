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

#[derive(Debug)]
pub struct Fingerprint<F: FingerprintRef> {
    inner: F,
}

pub trait FingerprintRef {}
impl FingerprintRef for Base64 {}
impl FingerprintRef for Raw {}
impl FingerprintRef for Hash {}

#[derive(Debug)]
pub struct Base64 {
    data: *const libc::c_char,
    _p: std::marker::PhantomData<std::ffi::CString>,
}

#[derive(Debug)]
pub struct Raw {
    data: *const u32,
    size: usize,
    _p: std::marker::PhantomData<[u32]>,
}

#[derive(Debug)]
pub struct Hash(u32);

impl From<Hash> for u32 {
    fn from(hash: Hash) -> Self {
        hash.0
    }
}

impl Drop for Base64 {
    fn drop(&mut self) {
        unsafe { chromaprint_dealloc(self.data as *mut std::ffi::c_void) };
    }
}

impl Drop for Raw {
    fn drop(&mut self) {
        unsafe { chromaprint_dealloc(self.data as *mut std::ffi::c_void) };
    }
}

impl Fingerprint<Base64> {
    pub fn get(&self) -> &str {
        let s = unsafe { std::ffi::CStr::from_ptr(self.inner.data) }.to_str().unwrap();
        s
    }
}

impl Fingerprint<Raw> {
    pub fn get(&self) -> &[u32] {
        let s = unsafe { std::slice::from_raw_parts(self.inner.data, self.inner.size) };
        s
    }
}

impl Fingerprint<Hash> {
    pub fn get(&self) -> u32 {
        self.inner.0
    }
}

impl TryFrom<Fingerprint<Raw>> for Fingerprint<Hash> {
    type Error = Error;
    fn try_from(raw: Fingerprint<Raw>) -> Result<Self> {
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

pub struct Context {
    ctx: *mut ChromaprintContext,
    algorithm: Algorithm,
}

impl Context {
    /// Creates a new Chromaprint context with the given algorithm. To use the default algorithm,
    /// call [`default`](Self::default).
    pub fn new(algorithm: Algorithm) -> Self {
        let ctx = unsafe { chromaprint_new(algorithm as i32) };
        Self { ctx, algorithm }
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// Returns the sample rate used internally by Chromaprint. If you want to avoid having Chromaprint internally
    /// resample audio, make sure to use this sample rate.
    pub fn sample_rate(&self) -> u32 {
        unsafe { chromaprint_get_sample_rate(self.ctx) as u32 }
    }

    /// Starts a fingerprinting session. Audio samples will be buffered by Chromaprint until [`finish`](Self::finish)
    /// is called.
    pub fn start(&mut self, sample_rate: u32, num_channels: u16) -> Result<()> {
        let rc = unsafe { chromaprint_start(self.ctx, sample_rate as i32, num_channels as i32) };
        if rc != 1 {
            return Err(Error::OperationFailed);
        }
        Ok(())
    }

    /// Feeds a set of audio samples to the fingerprinter.
    pub fn feed(&mut self, data: &[i16]) -> Result<()> {
        let rc = unsafe { chromaprint_feed(self.ctx, data.as_ptr(), data.len() as i32) };
        if rc != 1 {
            return Err(Error::OperationFailed);
        }
        Ok(())
    }

    /// Signals to the fingerprinter that the audio clip is complete. You must call this method before
    /// extracting a fingerprint.
    ///
    /// Important note: before calling [`finish`](Self::finish), you should provide at least 3 seconds worth of audio samples.
    /// The reason is that the size of the raw fingerprint is directly related to the amount of audio data fed
    /// to the fingerprinter.
    ///
    /// In general, the raw fingerprint size is `~= (duration_in_secs * 11025 - 4096) / 1365 - 15 - 4 + 1`
    ///
    /// See detailed discussion [here](https://github.com/acoustid/chromaprint/issues/45).
    pub fn finish(&mut self) -> Result<()> {
        let rc = unsafe { chromaprint_finish(self.ctx) };
        if rc != 1 {
            return Err(Error::OperationFailed);
        }
        Ok(())
    }

    /// Returns the raw fingerprint.
    pub fn get_fingerprint_raw(&self) -> Result<Fingerprint<Raw>> {
        let mut data_ptr = std::ptr::null_mut();
        let mut size: i32 = 0;
        let rc = unsafe { chromaprint_get_raw_fingerprint(self.ctx, &mut data_ptr, &mut size) };
        if rc != 1 {
            return Err(Error::OperationFailed);
        }
        Ok(Fingerprint {
            inner: Raw {
                data: data_ptr as *const _,
                size: size as usize,
                _p: std::marker::PhantomData,
            },
        })
    }

    /// Returns a hash of the raw fingerprint.
    ///
    /// Under the hood, Chromaprint computes a 32-bit [SimHash](https://en.wikipedia.org/wiki/SimHash) of the raw fingerprint.
    pub fn get_fingerprint_hash(&self) -> Result<Fingerprint<Hash>> {
        let mut hash: u32 = 0;
        let rc = unsafe { chromaprint_get_fingerprint_hash(self.ctx, &mut hash) };
        if rc != 1 {
            return Err(Error::OperationFailed);
        }
        Ok(Fingerprint { inner: Hash(hash) })
    }

    /// Returns a compressed version of the raw fingerprint in Base64 format. This is the format used by
    /// the [AcousticID](https://acoustid.org/) service.
    pub fn get_fingerprint_base64(&self) -> Result<Fingerprint<Base64>> {
        let mut out_ptr = std::ptr::null_mut();
        let rc = unsafe { chromaprint_get_fingerprint(self.ctx, &mut out_ptr) };
        if rc != 1 {
            return Err(Error::OperationFailed);
        }
        Ok(Fingerprint {
            inner: Base64 {
                data: out_ptr as *const _,
                _p: std::marker::PhantomData,
            },
        })
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

#[cfg(test)]
mod test {
    use std::{
        io::Read,
        path::{Path, PathBuf},
        str::FromStr,
    };

    use super::*;

    // Load raw audio as `i16` samples.
    fn load_audio(path: impl AsRef<Path>) -> Vec<i16> {
        let mut data = Vec::new();
        let mut buf = [0u8; 2];
        let mut f = std::fs::File::open(path).unwrap();
        while f.read_exact(&mut buf).is_ok() {
            data.push(i16::from_le_bytes(buf));
        }
        data
    }

    #[test]
    fn test_load_audio() {
        let audio_path = PathBuf::from_str(env!("CARGO_MANIFEST_DIR"))
            .unwrap()
            .join("resources")
            .join("test_mono_44100.raw");
        let data = load_audio(&audio_path);
        assert_eq!(data.len(), 2 * 44100); // 2 seconds @ 44.1 kHz
        assert_eq!(data[1000], 0);
        assert_eq!(data[2000], 107);
        assert_eq!(data[3000], 128);
    }

    #[test]
    #[ignore = "failing"]
    fn test_mono() {
        let audio_path = PathBuf::from_str(env!("CARGO_MANIFEST_DIR"))
            .unwrap()
            .join("resources")
            .join("test_mono_44100.raw");
        let data = load_audio(&audio_path);

        let mut ctx = Context::default();
        ctx.start(44100, 1).unwrap();
        ctx.feed(&data).unwrap();
        ctx.finish().unwrap();
        dbg!(ctx.get_fingerprint_hash().unwrap());
        dbg!(ctx.get_fingerprint_base64().unwrap());
        dbg!(ctx.get_fingerprint_raw().unwrap());
    }

    #[test]
    fn test_stereo() {
        let audio_path = PathBuf::from_str(env!("CARGO_MANIFEST_DIR"))
            .unwrap()
            .join("resources")
            .join("test_stereo_44100.raw");
        let data = load_audio(&audio_path);

        let mut ctx = Context::default();
        ctx.start(44100, 1).unwrap();
        ctx.feed(&data).unwrap();
        ctx.finish().unwrap();

        assert_eq!(ctx.get_fingerprint_hash().unwrap().get(), 3732003127);
        assert_eq!(
            ctx.get_fingerprint_raw().unwrap().get(),
            &[
                3740390231, 3739276119, 3730871573, 3743460629, 3743525173, 3744594229, 3727948087,
                1584920886, 1593302326, 1593295926, 1584907318,
            ]
        );
        assert_eq!(
            ctx.get_fingerprint_base64().unwrap().get(),
            "AQAAC0kkZUqYREkUnFAXHk8uuMZl6EfO4zu-4ABKFGESWIIMEQE"
        );
    }

    #[test]
    fn test_sample_rate() {
        let ctx = Context::default();
        assert_eq!(ctx.sample_rate(), 11025);
    }
}
