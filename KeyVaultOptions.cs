namespace KeyVaultTool {
    public enum OperationMode {
        Export,
        Import,
        Help
    };
    public class KeyVaultOptions {
        public string Address { set; get; }
        public string ClientId { set; get; }
        public string ClientSecret { set; get; }
        public OperationMode Mode { get; set; } = OperationMode.Export;
        public string File { get; set; } = "CON";
        public string Filter { get; set; } = ".*";
        public string Tags { get; set; } = ".*";
        public bool ShowVersions { get; set; }
    }
}
