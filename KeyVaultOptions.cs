using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace KeyVaultTool {
    public enum OperationMode {
        Export,
        Import,
        Help
    };
    public class KeyVaultOptions {
        public string Address { set; get; } = null!;
        public string TenantId { set; get; } = null!;
        public string ClientId { set; get; } = null!;
        public string ClientSecret { set; get; } = null!;
        public string Thumbprint { set; get; } = null!;
        public IList<string> AdditionallyAllowedTenants { get; } = ["*"];
        public OperationMode Mode { get; set; } = OperationMode.Export;
        public string File { get; set; } = "CON";
        public string Filter { get; set; } = ".*";
        public string Delimiter { get; set; } = "\t";
        public string Tags { get; set; } = ".*";
        public bool ShowVersions { get; set; }
        public bool Escape { get; set; }
        public string ContentTypeFilter { get; set; } = null!;
        public StoreLocation StoreLocation {get; set;} = StoreLocation.CurrentUser;
    }
}
