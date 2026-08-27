//! Coverage modes: hardware trace (Intel PT / AMD LBR / CoreSight), KCOV and
//! kcov-dataflow (function arguments and return values).

pub mod dataflow;
pub mod hw;
pub mod kcov;
