//! Safety / blast-radius controls (advisory §12, spoof guide §7).
//!
//! Every path that puts packets on the wire must pass through `authorize()`
//! before the first `send`. The guard enforces:
//!   * an explicit `--i-have-authorization` acknowledgement,
//!   * a hard ceiling on requested pps,
//!   * a hard ceiling on run duration.

use crate::cli::GlobalGuards;

#[derive(Debug)]
pub struct GuardError(pub String);

impl std::fmt::Display for GuardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "authorization/guard check failed: {}", self.0)
    }
}
impl std::error::Error for GuardError {}

/// Validate that a sending action is permitted. Returns Ok(()) or a GuardError
/// describing which control was violated. Call this BEFORE any packet is sent.
pub fn authorize(g: &GlobalGuards, requested_pps: u64, requested_secs: u64) -> Result<(), GuardError> {
    if !g.i_have_authorization {
        return Err(GuardError(
            "refusing to transmit: pass --i-have-authorization to confirm you own \
             or have written authorization to test the target (advisory §12)"
                .into(),
        ));
    }
    if requested_pps > g.max_pps {
        return Err(GuardError(format!(
            "requested {requested_pps} pps exceeds --max-pps ceiling {} (kill switch)",
            g.max_pps
        )));
    }
    if requested_secs > g.max_secs {
        return Err(GuardError(format!(
            "requested {requested_secs}s exceeds --max-secs ceiling {} (kill switch)",
            g.max_secs
        )));
    }
    Ok(())
}
