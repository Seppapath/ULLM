// SPDX-License-Identifier: Apache-2.0
//! PyO3 bindings: a synchronous `Session` exposed to Python.

use std::sync::Arc;

use ed25519_dalek::VerifyingKey;
use pyo3::exceptions::{PyConnectionError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyList;
use tokio::runtime::Runtime;
use ullm_client::Session;

/// A blocking wrapper around the async `ullm_client::Session`.
///
/// Builds a private tokio runtime per session; releases when dropped.
#[pyclass]
pub struct PySession {
    runtime: Arc<Runtime>,
    session: Option<Session>,
}

#[pymethods]
impl PySession {
    /// Connect to a gateway.
    ///
    /// `tls_fingerprint_hex` is optional: pass the gateway's pinned SHA-256
    /// cert fingerprint (64 hex chars) to use TLS, or `None` for plaintext.
    /// `tls_server_name` defaults to `"localhost"` when TLS is enabled.
    #[staticmethod]
    #[pyo3(signature = (url, trust_root_hex, tee_receipt_pk_hex, expected_weight_commit_hex, tls_fingerprint_hex=None, tls_server_name=None))]
    fn connect(
        url: &str,
        trust_root_hex: &str,
        tee_receipt_pk_hex: &str,
        expected_weight_commit_hex: &str,
        tls_fingerprint_hex: Option<&str>,
        tls_server_name: Option<&str>,
    ) -> PyResult<PySession> {
        let trust_root = parse_pk(trust_root_hex)?;
        let tee_pk = parse_pk(tee_receipt_pk_hex)?;
        let wc_bytes = hex::decode(expected_weight_commit_hex)
            .map_err(|e| PyValueError::new_err(format!("weight commit hex: {e}")))?;
        let weight_commit: [u8; 32] = wc_bytes
            .as_slice()
            .try_into()
            .map_err(|_| PyValueError::new_err("weight commit must be 32 bytes"))?;
        let tls = match tls_fingerprint_hex {
            Some(hex_fp) => {
                let bytes =
                    hex::decode(hex_fp).map_err(|e| PyValueError::new_err(format!("hex: {e}")))?;
                let arr: [u8; 32] = bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| PyValueError::new_err("fingerprint must be 32 bytes"))?;
                let server_name = tls_server_name.unwrap_or("localhost").to_string();
                Some(ullm_client::TlsPinning::pin(server_name, arr))
            }
            None => None,
        };
        let runtime = Arc::new(
            Runtime::new()
                .map_err(|e| PyConnectionError::new_err(format!("runtime: {e}")))?,
        );
        let url = url.to_string();
        let session = runtime
            .block_on(async move {
                Session::connect(&url, &trust_root, &tee_pk, weight_commit, tls).await
            })
            .map_err(|e| PyConnectionError::new_err(e.to_string()))?;
        Ok(PySession {
            runtime,
            session: Some(session),
        })
    }

    /// `session.tee_id_pk_hex() -> str`
    fn tee_id_pk_hex(&self) -> PyResult<String> {
        let session = self
            .session
            .as_ref()
            .ok_or_else(|| PyConnectionError::new_err("session closed"))?;
        Ok(hex::encode(session.tee_id_pk().as_bytes()))
    }

    /// `session.send(prompt) -> (list[str], dict)` — blocks until the whole
    /// response is received. Returns `(tokens, receipt)`.
    fn send(&mut self, py: Python<'_>, prompt: &str) -> PyResult<(Py<PyList>, PyObject)> {
        let session = self
            .session
            .as_mut()
            .ok_or_else(|| PyConnectionError::new_err("session closed"))?;
        let runtime = self.runtime.clone();
        let prompt = prompt.to_string();
        let (tokens, receipt) = runtime
            .block_on(async move {
                let mut stream = session.send(&prompt).await?;
                let mut tokens: Vec<String> = Vec::new();
                while let Some(t) = stream.next_token().await? {
                    tokens.push(t);
                }
                let receipt = stream.finalize().await?;
                Ok::<_, ullm_core::Error>((tokens, receipt))
            })
            .map_err(|e| PyConnectionError::new_err(e.to_string()))?;

        let list = PyList::new_bound(py, tokens);
        let dict = pyo3::types::PyDict::new_bound(py);
        dict.set_item("model", &receipt.receipt.model)?;
        dict.set_item("input_tokens", receipt.receipt.input_tokens)?;
        dict.set_item("output_tokens", receipt.receipt.output_tokens)?;
        dict.set_item("epoch", receipt.receipt.epoch)?;
        dict.set_item("issued_at_unix", receipt.receipt.issued_at_unix)?;
        dict.set_item("session_id", hex::encode(receipt.receipt.session.0))?;
        Ok((list.unbind(), dict.into_any().unbind()))
    }
}

fn parse_pk(hex_str: &str) -> PyResult<VerifyingKey> {
    let bytes = hex::decode(hex_str).map_err(|e| PyValueError::new_err(format!("hex: {e}")))?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| PyValueError::new_err("public key must be 32 bytes"))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| PyValueError::new_err(format!("pk: {e}")))
}

#[pymodule]
fn ullm_py(_py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PySession>()?;
    Ok(())
}
