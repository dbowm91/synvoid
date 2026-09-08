use bytes::Bytes;
use http_body_util::BodyExt;
use metrics::counter;
use std::net::IpAddr;

use crate::shared_handler::{collect_body_with_chunk_waf, BodyCollectionProtocol};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyPolicyError {
    BlockedByWaf,
    BodyTooLarge,
}

impl BodyPolicyError {
    /// Project a body-policy failure onto the canonical enforcement contract.
    ///
    /// Both variants deny the request (fail closed): `BlockedByWaf` renders
    /// 403, `BodyTooLarge` renders 413. The mapping is exhaustive so a new
    /// variant cannot silently become an allow.
    pub const fn candidate(&self) -> synvoid_core::enforcement::EnforcementCandidate {
        use synvoid_core::enforcement::{
            EnforcementCandidate, EnforcementClass, EnforcementReason, EnforcementSource,
        };
        match self {
            Self::BlockedByWaf => EnforcementCandidate::new(
                EnforcementClass::Block,
                EnforcementSource::StreamingBodyScan,
                EnforcementReason::BodyBlocked,
            ),
            Self::BodyTooLarge => EnforcementCandidate::new(
                EnforcementClass::Block,
                EnforcementSource::StreamingBodyScan,
                EnforcementReason::BodyTooLarge,
            ),
        }
    }
}

pub trait RequestBodyWaf {
    fn streaming(&self) -> Option<Box<dyn crate::shared_handler::StreamingWafScanner>>;
    fn check_request_body(&self, chunk: &[u8]) -> (bool, Option<synvoid_waf::WafDecision>);
}

const MAX_WAF_BODY_SIZE: usize = 1024 * 1024;
const CHUNK_WAF_SCAN_SIZE: usize = 64 * 1024;
const CHUNK_WAF_THRESHOLD: usize = 256 * 1024;

pub async fn collect_and_scan_request_body<W>(
    body: hyper::body::Incoming,
    waf: &W,
    client_ip: IpAddr,
    content_length: Option<usize>,
    max_streaming_body_size: usize,
) -> Result<(Bytes, u64), BodyPolicyError>
where
    W: RequestBodyWaf,
{
    let mut request_body_size: u64 = 0;
    let full_body = if let Some(cl) = content_length {
        if cl > CHUNK_WAF_THRESHOLD {
            match collect_body_with_chunk_waf(
                body,
                waf.streaming(),
                client_ip,
                BodyCollectionProtocol::Http,
                Some(&mut request_body_size),
                content_length,
                max_streaming_body_size,
            )
            .await
            {
                Ok(body) => body,
                Err(()) => return Err(BodyPolicyError::BlockedByWaf),
            }
        } else {
            match body.collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => Bytes::from_static(&[]),
            }
        }
    } else {
        match collect_body_with_chunk_waf(
            body,
            waf.streaming(),
            client_ip,
            BodyCollectionProtocol::Http,
            Some(&mut request_body_size),
            content_length,
            max_streaming_body_size,
        )
        .await
        {
            Ok(body) => body,
            Err(()) => return Err(BodyPolicyError::BodyTooLarge),
        }
    };

    if full_body.len() > MAX_WAF_BODY_SIZE && !full_body.is_empty() {
        let body_len = full_body.len();
        for offset in (0..body_len).step_by(CHUNK_WAF_SCAN_SIZE) {
            let end = std::cmp::min(offset + CHUNK_WAF_SCAN_SIZE, body_len);
            let chunk = &full_body[offset..end];
            let (_, body_decision) = waf.check_request_body(chunk);
            if let Some(synvoid_waf::WafDecision::Drop | synvoid_waf::WafDecision::Block(_, _)) =
                body_decision
            {
                tracing::warn!(
                    client_ip = %client_ip,
                    offset = offset,
                    size = body_len,
                    "Large request body blocked by WAF at offset {}",
                    offset
                );
                counter!("synvoid.http.large_body_blocked").increment(1);
                return Err(BodyPolicyError::BlockedByWaf);
            }
        }
        tracing::debug!(
            client_ip = %client_ip,
            size = body_len,
            "Large request body scanned by WAF ({} chunks)",
            body_len.div_ceil(CHUNK_WAF_SCAN_SIZE)
        );
    }

    Ok((full_body, request_body_size))
}

#[cfg(test)]
mod tests {
    use super::*;
    use synvoid_core::enforcement::{EnforcementClass, EnforcementSource};

    #[test]
    fn body_policy_errors_are_terminal_and_fail_closed() {
        // Both variants must deny: a new BodyPolicyError variant that maps
        // to Allow would be a fail-open regression.
        for error in [BodyPolicyError::BlockedByWaf, BodyPolicyError::BodyTooLarge] {
            let candidate = error.candidate();
            assert_eq!(candidate.class, EnforcementClass::Block);
            assert!(candidate.class.is_terminal());
            assert_eq!(candidate.source, EnforcementSource::StreamingBodyScan);
        }
        assert_eq!(
            BodyPolicyError::BlockedByWaf.candidate().reason.as_str(),
            "body_blocked"
        );
        assert_eq!(
            BodyPolicyError::BodyTooLarge.candidate().reason.as_str(),
            "body_too_large"
        );
    }
}
