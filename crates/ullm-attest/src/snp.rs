// SPDX-License-Identifier: Apache-2.0
//! AMD SEV-SNP Attestation Report parser.
//!
//! Layout (little-endian where multi-byte; per AMD SEV-SNP Firmware ABI v1.55+):
//!
//! ```text
//! version             u32
//! guest_svn           u32
//! policy              u64
//! family_id           [u8; 16]
//! image_id            [u8; 16]
//! vmpl                u32
//! signature_algo      u32
//! current_tcb         u64
//! platform_info       u64
//! flags               u32   // bit 0 = AUTHOR_KEY_EN
//! reserved_0          u32
//! report_data         [u8; 64]
//! measurement         [u8; 48]
//! host_data           [u8; 32]
//! id_key_digest       [u8; 48]
//! author_key_digest   [u8; 48]
//! report_id           [u8; 32]
//! report_id_ma        [u8; 32]
//! reported_tcb        u64
//! cpuid_fam_id        u8
//! cpuid_mod_id        u8
//! cpuid_step          u8
//! reserved_1          [u8; 21]
//! chip_id             [u8; 64]
//! committed_tcb       u64
//! current_build       u8
//! current_minor       u8
//! current_major       u8
//! reserved_2          u8
//! committed_build     u8
//! committed_minor     u8
//! committed_major     u8
//! reserved_3          u8
//! launch_tcb          u64
//! reserved_4          [u8; 168]
//! signature           [u8; 512]
//! ```
//!
//! Total: 1184 bytes.

use ullm_core::{Error, Result};

pub const REPORT_LEN: usize = 1184;
pub const SIGNATURE_LEN: usize = 512;

#[derive(Debug, Clone)]
pub struct SnpReport {
    pub version: u32,
    pub guest_svn: u32,
    pub policy: u64,
    pub family_id: [u8; 16],
    pub image_id: [u8; 16],
    pub vmpl: u32,
    pub signature_algo: u32,
    pub current_tcb: u64,
    pub platform_info: u64,
    pub flags: u32,
    pub report_data: [u8; 64],
    pub measurement: [u8; 48],
    pub host_data: [u8; 32],
    pub id_key_digest: [u8; 48],
    pub author_key_digest: [u8; 48],
    pub report_id: [u8; 32],
    pub report_id_ma: [u8; 32],
    pub reported_tcb: u64,
    pub chip_id: [u8; 64],
    pub committed_tcb: u64,
    pub launch_tcb: u64,
    pub signature: [u8; SIGNATURE_LEN],
}

impl SnpReport {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < REPORT_LEN {
            return Err(Error::AttestationFailed(format!(
                "SNP report shorter than {} bytes (got {})",
                REPORT_LEN,
                bytes.len()
            )));
        }
        let mut c = Cursor::new(bytes);
        let version = c.read_u32_le()?;
        let guest_svn = c.read_u32_le()?;
        let policy = c.read_u64_le()?;
        let family_id = c.read_array::<16>()?;
        let image_id = c.read_array::<16>()?;
        let vmpl = c.read_u32_le()?;
        let signature_algo = c.read_u32_le()?;
        let current_tcb = c.read_u64_le()?;
        let platform_info = c.read_u64_le()?;
        let flags = c.read_u32_le()?;
        let _reserved_0 = c.read_u32_le()?;
        let report_data = c.read_array::<64>()?;
        let measurement = c.read_array::<48>()?;
        let host_data = c.read_array::<32>()?;
        let id_key_digest = c.read_array::<48>()?;
        let author_key_digest = c.read_array::<48>()?;
        let report_id = c.read_array::<32>()?;
        let report_id_ma = c.read_array::<32>()?;
        let reported_tcb = c.read_u64_le()?;
        let _cpuid_fam_id = c.read_u8()?;
        let _cpuid_mod_id = c.read_u8()?;
        let _cpuid_step = c.read_u8()?;
        let _reserved_1 = c.read_array::<21>()?;
        let chip_id = c.read_array::<64>()?;
        let committed_tcb = c.read_u64_le()?;
        let _current_build = c.read_u8()?;
        let _current_minor = c.read_u8()?;
        let _current_major = c.read_u8()?;
        let _reserved_2 = c.read_u8()?;
        let _committed_build = c.read_u8()?;
        let _committed_minor = c.read_u8()?;
        let _committed_major = c.read_u8()?;
        let _reserved_3 = c.read_u8()?;
        let launch_tcb = c.read_u64_le()?;
        let _reserved_4 = c.read_array::<168>()?;
        let signature = c.read_array::<SIGNATURE_LEN>()?;
        Ok(Self {
            version,
            guest_svn,
            policy,
            family_id,
            image_id,
            vmpl,
            signature_algo,
            current_tcb,
            platform_info,
            flags,
            report_data,
            measurement,
            host_data,
            id_key_digest,
            author_key_digest,
            report_id,
            report_id_ma,
            reported_tcb,
            chip_id,
            committed_tcb,
            launch_tcb,
            signature,
        })
    }

    pub fn report_data(&self) -> &[u8; 64] {
        &self.report_data
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn read_slice(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() - self.pos < n {
            return Err(Error::AttestationFailed("SNP report truncated".into()));
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }
    fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let s = self.read_slice(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }
    fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_array::<1>()?[0])
    }
    fn read_u32_le(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }
    fn read_u64_le(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.read_array::<8>()?))
    }
}

/// Build a synthetic SNP report for tests.
pub fn synthesize_report(report_data: [u8; 64], measurement: [u8; 48]) -> Vec<u8> {
    let mut out = vec![0u8; REPORT_LEN];
    out[0..4].copy_from_slice(&3u32.to_le_bytes()); // version
    // skip to report_data at offset 80
    out[80..80 + 64].copy_from_slice(&report_data);
    // measurement at offset 144
    out[144..144 + 48].copy_from_slice(&measurement);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_synthetic_report() {
        let rd = [11u8; 64];
        let m = [22u8; 48];
        let bytes = synthesize_report(rd, m);
        let r = SnpReport::parse(&bytes).unwrap();
        assert_eq!(r.version, 3);
        assert_eq!(r.report_data, rd);
        assert_eq!(r.measurement, m);
    }

    #[test]
    fn rejects_short_buffer() {
        assert!(SnpReport::parse(&[0u8; 100]).is_err());
    }
}
