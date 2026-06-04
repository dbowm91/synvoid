use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq)]
pub enum ChallengeResult {
    Passed,
    NotSet,
    Failed,
    RateLimited,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ChallengeType {
    #[default]
    None,
    PowChallenge,
    MeshPowChallenge,
    CssChallenge,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ChallengePriority {
    #[default]
    PowThenCss,
    CssThenPow,
    PowOnly,
    CssOnly,
    MeshPowThenCss,
    MeshPowOnly,
}
