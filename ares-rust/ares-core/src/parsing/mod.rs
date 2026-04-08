//! Regex-based output parsing for security tool outputs.
//!
//! This module replaces the Python `result_processing.py` parsing functions,
//! providing parsers for secretsdump, Kerberos hashes, NTLM hashes, host
//! discovery, delegation enumeration, domain SIDs, and share enumeration.

mod delegation;
mod domain_sid;
mod hosts;
mod kerberos;
mod ntlm;
mod secretsdump;
mod shares;
mod types;

pub use delegation::*;
pub use domain_sid::*;
pub use hosts::*;
pub use kerberos::*;
pub use ntlm::*;
pub use secretsdump::*;
pub use shares::*;
pub use types::*;
