use crate::protocol::{MeshMessage, ServerlessInvokeRequest};
use crate::transport::{MeshTransport, MeshTransportError};

impl MeshTransport {
    #[allow(unused)]
    pub(crate) async fn send_serverless_invoke_request(
        &self,
        target_node_id: &str,
        function_name: &str,
        caller_node_id: &str,
    ) -> Result<(), MeshTransportError> {
        let request =
            ServerlessInvokeRequest::new(function_name.to_string(), caller_node_id.to_string());

        let msg = MeshMessage::ServerlessInvokeRequest(request);

        self.send_message_to_peer(target_node_id, &msg).await?;

        tracing::debug!(
            "Sent ServerlessInvokeRequest for '{}' to node {}",
            function_name,
            target_node_id
        );

        Ok(())
    }
}
