// SPDX-License-Identifier: Apache-2.0
//! Intel TDX DCAP Quote v4 parser.
//!
//! Layout (little-endian, all field sizes in bytes):
//!
//! ```text
//! Header (48):
//!   version         u16   // 4
//!   att_key_type    u16   // 2 = ECDSA-P256
//!   tee_type        u32   // 0x81 = TDX
//!   reserved        u32
//!   qe_vendor_id    [u8; 16]
//!   user_data       [u8; 20]
//!
//! TD Report (584):
//!   tee_tcb_svn     [u8; 16]
//!   mrseam          [u8; 48]
//!   mrsignerseam    [u8; 48]
//!   seamattributes  [u8; 8]
//!   tdattributes    [u8; 8]
//!   xfam            [u8; 8]
//!   mrtd            [u8; 48]
//!   mrconfigid      [u8; 48]
//!   mrowner         [u8; 48]
//!   mrownerconfig   [u8; 48]
//!   rtmr0..rtmr3    [u8; 48] x 4
//!   report_data     [u8; 64]
//!
//! Signature data length: u32, then `signature_data` bytes (ECDSA P-256
//! signature + attestation key + Quoting Enclave certification chain).
//! ```
//!
//! Reference: Intel TDX DCAP Quoting Library API, March 2024.

use ullm_core::{Error, Result};

pub const HEADER_LEN: usize = 48;
pub const TD_REPORT_LEN: usize = 584;
pub const ECDSA_P256_SIGNATURE_LEN: usize = 64;
pub const ECDSA_P256_PUBLIC_KEY_LEN: usize = 64;
pub const TEE_TYPE_TDX: u32 = 0x81;
pub const ATT_KEY_TYPE_ECDSA_P256: u16 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxQuote {
    pub header: QuoteHeader,
    pub td_report: TdReport,
    pub signature: TdxSignatureData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuoteHeader {
    pub version: u16,
    pub att_key_type: u16,
    pub tee_type: u32,
    pub qe_vendor_id: [u8; 16],
    pub user_data: [u8; 20],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdReport {
    pub tee_tcb_svn: [u8; 16],
    pub mrseam: [u8; 48],
    pub mrsignerseam: [u8; 48],
    pub seamattributes: [u8; 8],
    pub tdattributes: [u8; 8],
    pub xfam: [u8; 8],
    pub mrtd: [u8; 48],
    pub mrconfigid: [u8; 48],
    pub mrowner: [u8; 48],
    pub mrownerconfig: [u8; 48],
    pub rtmr0: [u8; 48],
    pub rtmr1: [u8; 48],
    pub rtmr2: [u8; 48],
    pub rtmr3: [u8; 48],
    pub report_data: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TdxSignatureData {
    pub ecdsa_signature: [u8; ECDSA_P256_SIGNATURE_LEN],
    pub attestation_key: [u8; ECDSA_P256_PUBLIC_KEY_LEN],
    pub cert_data: Vec<u8>,
}

impl TdxQuote {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let header = parse_header(&mut cursor)?;
        if header.tee_type != TEE_TYPE_TDX {
            return Err(Error::AttestationFailed(format!(
                "expected TEE_TYPE_TDX, got {:#x}",
                header.tee_type
            )));
        }
        if header.att_key_type != ATT_KEY_TYPE_ECDSA_P256 {
            return Err(Error::AttestationFailed(format!(
                "expected ECDSA-P256 attestation key, got {}",
                header.att_key_type
            )));
        }
        let td_report = parse_td_report(&mut cursor)?;
        let sig_len = cursor.read_u32_le()? as usize;
        if cursor.remaining() < sig_len {
            return Err(Error::AttestationFailed(format!(
                "signature_data truncated: declared {} bytes, {} remain",
                sig_len,
                cursor.remaining()
            )));
        }
        if sig_len < ECDSA_P256_SIGNATURE_LEN + ECDSA_P256_PUBLIC_KEY_LEN {
            return Err(Error::AttestationFailed(
                "signature_data shorter than fixed prefix".into(),
            ));
        }
        let sig_bytes = cursor.read_slice(sig_len)?;
        let ecdsa_signature: [u8; ECDSA_P256_SIGNATURE_LEN] = sig_bytes[..ECDSA_P256_SIGNATURE_LEN]
            .try_into()
            .expect("checked length");
        let attestation_key: [u8; ECDSA_P256_PUBLIC_KEY_LEN] = sig_bytes
            [ECDSA_P256_SIGNATURE_LEN..ECDSA_P256_SIGNATURE_LEN + ECDSA_P256_PUBLIC_KEY_LEN]
            .try_into()
            .expect("checked length");
        let cert_data = sig_bytes[ECDSA_P256_SIGNATURE_LEN + ECDSA_P256_PUBLIC_KEY_LEN..].to_vec();
        Ok(Self {
            header,
            td_report,
            signature: TdxSignatureData {
                ecdsa_signature,
                attestation_key,
                cert_data,
            },
        })
    }

    pub fn report_data(&self) -> &[u8; 64] {
        &self.td_report.report_data
    }
}

fn parse_header(c: &mut Cursor<'_>) -> Result<QuoteHeader> {
    if c.remaining() < HEADER_LEN {
        return Err(Error::AttestationFailed(format!(
            "TDX quote shorter than header ({} bytes)",
            c.remaining()
        )));
    }
    let version = c.read_u16_le()?;
    let att_key_type = c.read_u16_le()?;
    let tee_type = c.read_u32_le()?;
    let _reserved = c.read_u32_le()?;
    let qe_vendor_id = c.read_array::<16>()?;
    let user_data = c.read_array::<20>()?;
    Ok(QuoteHeader {
        version,
        att_key_type,
        tee_type,
        qe_vendor_id,
        user_data,
    })
}

fn parse_td_report(c: &mut Cursor<'_>) -> Result<TdReport> {
    if c.remaining() < TD_REPORT_LEN {
        return Err(Error::AttestationFailed(format!(
            "TD report truncated ({} bytes remain)",
            c.remaining()
        )));
    }
    Ok(TdReport {
        tee_tcb_svn: c.read_array::<16>()?,
        mrseam: c.read_array::<48>()?,
        mrsignerseam: c.read_array::<48>()?,
        seamattributes: c.read_array::<8>()?,
        tdattributes: c.read_array::<8>()?,
        xfam: c.read_array::<8>()?,
        mrtd: c.read_array::<48>()?,
        mrconfigid: c.read_array::<48>()?,
        mrowner: c.read_array::<48>()?,
        mrownerconfig: c.read_array::<48>()?,
        rtmr0: c.read_array::<48>()?,
        rtmr1: c.read_array::<48>()?,
        rtmr2: c.read_array::<48>()?,
        rtmr3: c.read_array::<48>()?,
        report_data: c.read_array::<64>()?,
    })
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn read_slice(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(Error::AttestationFailed(format!(
                "read past end ({} requested, {} remain)",
                n,
                self.remaining()
            )));
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
    fn read_u16_le(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.read_array::<2>()?))
    }
    fn read_u32_le(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read_array::<4>()?))
    }
}

/// Build a synthetic quote for tests and fuzzers.
pub fn synthesize_quote(report_data: [u8; 64], mrtd: [u8; 48]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + TD_REPORT_LEN + 8 + 128);
    // header
    out.extend_from_slice(&4u16.to_le_bytes()); // version
    out.extend_from_slice(&ATT_KEY_TYPE_ECDSA_P256.to_le_bytes());
    out.extend_from_slice(&TEE_TYPE_TDX.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // reserved
    out.extend_from_slice(&[0u8; 16]); // qe_vendor_id
    out.extend_from_slice(&[0u8; 20]); // user_data
    // TD report
    out.extend_from_slice(&[0u8; 16]); // tee_tcb_svn
    out.extend_from_slice(&[0u8; 48]); // mrseam
    out.extend_from_slice(&[0u8; 48]); // mrsignerseam
    out.extend_from_slice(&[0u8; 8]); // seamattributes
    out.extend_from_slice(&[0u8; 8]); // tdattributes
    out.extend_from_slice(&[0u8; 8]); // xfam
    out.extend_from_slice(&mrtd);
    out.extend_from_slice(&[0u8; 48]); // mrconfigid
    out.extend_from_slice(&[0u8; 48]); // mrowner
    out.extend_from_slice(&[0u8; 48]); // mrownerconfig
    out.extend_from_slice(&[0u8; 48]); // rtmr0
    out.extend_from_slice(&[0u8; 48]); // rtmr1
    out.extend_from_slice(&[0u8; 48]); // rtmr2
    out.extend_from_slice(&[0u8; 48]); // rtmr3
    out.extend_from_slice(&report_data);
    // signature_data: 64-byte sig + 64-byte att key + empty cert data
    let sig_data_len = (ECDSA_P256_SIGNATURE_LEN + ECDSA_P256_PUBLIC_KEY_LEN) as u32;
    out.extend_from_slice(&sig_data_len.to_le_bytes());
    out.extend_from_slice(&[0u8; ECDSA_P256_SIGNATURE_LEN]);
    out.extend_from_slice(&[0u8; ECDSA_P256_PUBLIC_KEY_LEN]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_synthetic_quote() {
        let rd = [7u8; 64];
        let mrtd = [9u8; 48];
        let bytes = synthesize_quote(rd, mrtd);
        let q = TdxQuote::parse(&bytes).unwrap();
        assert_eq!(q.header.tee_type, TEE_TYPE_TDX);
        assert_eq!(q.header.version, 4);
        assert_eq!(q.td_report.mrtd, mrtd);
        assert_eq!(*q.report_data(), rd);
        assert_eq!(q.signature.cert_data.len(), 0);
    }

    #[test]
    fn rejects_wrong_tee_type() {
        let mut bytes = synthesize_quote([0; 64], [0; 48]);
        bytes[4..8].copy_from_slice(&0u32.to_le_bytes()); // tee_type = SGX
        assert!(TdxQuote::parse(&bytes).is_err());
    }

    #[test]
    fn rejects_short_buffer() {
        assert!(TdxQuote::parse(&[0u8; 10]).is_err());
    }
}
