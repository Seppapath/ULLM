# SPDX-License-Identifier: Apache-2.0
"""ullm — Python client for the Ultimate Private LLM Communication Layer.

Example:
    import ullm
    s = ullm.PySession.connect("http://localhost:9000", trust_root_hex, tee_pk_hex)
    tokens, receipt = s.send("hello world")
    print("".join(tokens))
"""
from ._ullm_py import PySession  # type: ignore

__all__ = ["PySession"]
