#[derive(Debug, Clone)]
pub struct QuorumSignature {
    pub node_id: String,
    pub signature: Vec<u8>,
    pub timestamp: u64,
    pub signer_public_key: Option<String>,
}

pub struct QuorumRequest;

impl QuorumRequest {
    pub fn required_signatures(total_nodes: usize) -> usize {
        Self::required_signatures_for(total_nodes)
    }

    pub fn required_signatures_for(node_count: usize) -> usize {
        if node_count == 0 {
            return 1;
        }
        (node_count * 2 / 3) + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_required_signatures() {
        assert_eq!(QuorumRequest::required_signatures(3), 3);
        assert_eq!(QuorumRequest::required_signatures(4), 3);
        assert_eq!(QuorumRequest::required_signatures(5), 4);
        assert_eq!(QuorumRequest::required_signatures(6), 5);
        assert_eq!(QuorumRequest::required_signatures_for(0), 1);
    }
}
