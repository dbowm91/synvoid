use clap::{Parser, Subcommand};

#[derive(Parser)]
pub struct MeshArgs {
    #[command(subcommand)]
    pub command: MeshCommand,
}

#[derive(Subcommand, Debug)]
pub enum MeshCommand {
    #[command(about = "Bootstrap a new global node for the mesh network")]
    BootstrapGlobal {
        #[arg(long, help = "Network ID for isolation")]
        network_id: Option<String>,

        #[arg(long, help = "Generate a new global node key")]
        generate_key: bool,

        #[arg(long, help = "Output config to file")]
        output: Option<String>,

        #[arg(long, help = "Bind address for the global node")]
        bind_address: Option<String>,

        #[arg(long, default_value = "5001", help = "Port for mesh communication")]
        port: u16,
    },

    #[command(about = "Generate a secure key for global node authentication")]
    GenerateKey,

    #[command(about = "Generate a new signing key for node identity")]
    GenerateSigningKey {
        #[arg(long, help = "Output path for the signing key")]
        output: Option<String>,

        #[arg(long, help = "Show the public key and node ID")]
        show: bool,
    },

    #[command(about = "Print the current node's signing key info")]
    ShowSigningKey,

    #[command(about = "Print example configuration for mesh networking")]
    PrintConfig {
        #[arg(long, help = "Include example seeds")]
        with_seeds: bool,
    },

    #[command(about = "List pending organization registration requests")]
    OrgListPending,

    #[command(about = "Approve a pending organization registration")]
    OrgApprove {
        #[arg(help = "Request ID from org-pending command")]
        request_id: String,

        #[arg(long, help = "Organization name (override)")]
        org_name: Option<String>,

        #[arg(long, default_value = "365", help = "Validity in days for initial key")]
        validity_days: u64,

        #[arg(long, help = "Default tier for the organization")]
        default_tier: Option<u32>,
    },

    #[command(about = "Reject a pending organization registration")]
    OrgReject {
        #[arg(help = "Request ID from org-pending command")]
        request_id: String,

        #[arg(help = "Reason for rejection")]
        reason: String,
    },

    #[command(about = "Invite a node to an organization")]
    OrgInvite {
        #[arg(help = "Organization ID")]
        org_id: String,

        #[arg(help = "Node ID to invite")]
        node_id: String,

        #[arg(long, help = "Validity in hours for the invitation")]
        validity_hours: Option<u64>,
    },

    #[command(about = "List members of an organization")]
    OrgListMembers {
        #[arg(help = "Organization ID")]
        org_id: String,
    },

    #[command(about = "Remove a member from an organization")]
    OrgRemoveMember {
        #[arg(help = "Organization ID")]
        org_id: String,

        #[arg(help = "Node ID to remove")]
        node_id: String,
    },

    #[command(about = "Issue a tier key to an organization")]
    OrgIssueKey {
        #[arg(help = "Organization ID")]
        org_id: String,

        #[arg(long, help = "Tier level (0=free, 1=paid, etc)")]
        tier: u32,

        #[arg(long, default_value = "365", help = "Validity in days")]
        validity_days: u64,

        #[arg(long, help = "Output key to file")]
        output: Option<String>,
    },

    #[command(about = "Revoke a tier key from an organization")]
    OrgRevokeKey {
        #[arg(help = "Organization ID")]
        org_id: String,

        #[arg(help = "Key ID to revoke")]
        key_id: String,
    },

    #[command(about = "List organizations")]
    OrgList,

    #[command(about = "Generate an organization signing key")]
    OrgGenerateKey {
        #[arg(help = "Organization ID")]
        org_id: String,

        #[arg(long, help = "Output key to file")]
        output: Option<String>,
    },

    #[command(about = "Issue a member certificate to a node")]
    OrgIssueMemberCert {
        #[arg(help = "Organization ID")]
        org_id: String,

        #[arg(help = "Node ID to certificate")]
        node_id: String,

        #[arg(long, default_value = "365", help = "Validity in days")]
        validity_days: u64,

        #[arg(long, help = "Output certificate to file")]
        output: Option<String>,
    },

    #[command(about = "List member certificates for an organization")]
    OrgListCerts {
        #[arg(help = "Organization ID")]
        org_id: String,
    },

    #[command(about = "Revoke a member certificate")]
    OrgRevokeCert {
        #[arg(help = "Organization ID")]
        org_id: String,

        #[arg(help = "Certificate ID to revoke")]
        cert_id: String,
    },

    #[command(about = "Generate a new genesis key (first-time setup)")]
    GenerateGenesisKey {
        #[arg(long, help = "Output genesis key to file")]
        output: Option<String>,
    },

    #[command(about = "Create an invitation for a new global node")]
    GlobalNodeInvite {
        #[arg(help = "Mesh ID of the node to invite")]
        mesh_id: String,

        #[arg(long, help = "Output invitation to file")]
        output: Option<String>,
    },

    #[command(about = "Add a global node using an invitation")]
    GlobalNodeAdd {
        #[arg(help = "Invitation token")]
        invitation: String,

        #[arg(help = "Node ID of the new global node")]
        node_id: String,

        #[arg(help = "Public key of the new global node")]
        public_key: String,
    },

    #[command(about = "Remove a global node")]
    GlobalNodeRemove {
        #[arg(help = "Node ID of the global node to remove")]
        node_id: String,
    },

    #[command(about = "List global nodes in the network")]
    GlobalNodeList,
}
