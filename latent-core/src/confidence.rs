//!
//! Ayman PROJECT, 2026
//! Latent
//! File description:
//! Confidence scale and resolution method
//!

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Confidence {
    L0Intact,
    L1LocalTemplate,
    L2ExternalCorpus,
    L3Structural,
    L4Raw,
}

impl Confidence {
    pub fn tag(self) -> &'static str {
        use Confidence::*;
        match self {
            L0Intact => "L0",
            L1LocalTemplate => "L1",
            L2ExternalCorpus => "L2",
            L3Structural => "L3",
            L4Raw => "L4",
        }
    }

    pub fn is_reconstructed(self) -> bool {
        self != Confidence::L0Intact
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Method {
    LocalTemplate,
    SameSource,
    ExternalCorpus,
    StructuralInference,
    RawOnly,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_orders_intact_before_raw() {
        assert!(Confidence::L0Intact < Confidence::L1LocalTemplate);
        assert!(Confidence::L1LocalTemplate < Confidence::L2ExternalCorpus);
        assert!(Confidence::L3Structural < Confidence::L4Raw);
        assert!(Confidence::L0Intact < Confidence::L4Raw);
    }

    #[test]
    fn tags() {
        assert_eq!(Confidence::L0Intact.tag(), "L0");
        assert_eq!(Confidence::L4Raw.tag(), "L4");
    }

    #[test]
    fn only_l0_is_observed() {
        assert!(!Confidence::L0Intact.is_reconstructed());
        assert!(Confidence::L1LocalTemplate.is_reconstructed());
        assert!(Confidence::L4Raw.is_reconstructed());
    }
}
