# KeyVault

Azure Key Vault Tool to import/export secrets, keys and certificates.

## dotnet run KeyVault.cs

KeyVault.cs requires .NET SDK version 10 or later.

```cmd
dotnet run KeyVault.cs -- --help
```

## Build

```cmd
dotnet publish KeyVault.cs -c Release -p:AssemblyVersion=1.0.0.0 -p:Version=1.0.0.0 -p:PublishSingleFile=true -r win-x64 --self-contained false -o c:\tools
```

## Samples

1. Show help

    ```cmd
    c:\>c:\tools\keyvault
    info: KeyVaultTool.KeyVaultService[0]
      Version: 1.0.0.0, Author: Kai Wang

      Options:
        -a, --address        Azure Key Vault addresss.
        -c, --config         Config file (json|xml|ini|yaml|yml)
        -t, --tenant-id      Tenant id
        -u, --client-id      Client id
        -p, --client-secret  Client secret
        -m, --mode           Import/Export. Default: Export
        -o, --file           File path to be used for import or export
        -s, --scopes         Scopes. Default: secrets,keys,certificates
        -f, --filter         Filter rules regular expression
        -v, --show-versions  Show versions.  Default: false. Format: {a.Updated.Value:O}{versionName}   {value}

      Samples:
        KeyVault --address https://sample.vault.azure.net/
        KeyVault --address https://sample.vault.azure.net/ --filter .*Vault.*
        KeyVault --address https://sample.vault.azure.net/ --tenant-id {tenant} --client-id {guid} --client-secret {secret} --mode import --file output.txt
        KeyVault --address https://sample.vault.azure.net/ --tenant-id {tenant} --client-id {guid} --client-secret {secret} --mode export --file output.txt
        KeyVault --config config.yml

    ```

1. Export key vault content with default Azure credential (Environmental Variables, Azure CLI, Visual Studio, or Visual Studio)

    ```cmd
    REM Export content into console output (stdout)
    keyvault --Address https://{name}.vault.azure.net/
    REM Export content into file instead of console output (stdout)
    keyvault --address https://{name}.vault.azure.net --filter .*Vault.*  --file output.txt
    ```

1. Export key vault content with SPN:

    ```cmd
    keyvault --Address https://{name}.vault.azure.net/ --client-id {guid} --client-secret "****"
    ```

1. Import from file into Key Vault:

    ```cmd
    keyvault --Address "https://{name}.vault.azure.net/" --client-id {guid} --client-secret "****" --mode Import --file kv.txt
    ```

1. Execute KeyVaultTool with configuration file:

    ```cmd
    keyvault --config config.yml
    ```

    Sample config.yml

    ```yaml
    Address: https://{name}.vault.azure.net/    # Key Vault address (Required).
    # TenantId: {TenantId}                      # Default or customized Entra Id tenant.
    # ClientId:                                 # Managed Identity Authentication.
    # ClientSecret:                             # SPN Authentication with ClientId and ClientSecret.
    # Thumbprint:                               # SPN Authentication with Certifivate by thrumbprint.
    Mode: Export                                # Import | Export | Help
    File: kv.tsv                                # Output file. Default to Console output (stdout).
    ShowVersions: false                         # List version history.
    ContentTypeFilter: ".*"                     # or: application/x-pem-file | application/x-pkcs12
    Escape: true                                # Escape non-printable chars (\n, \r, \t).
    ```

    Sample kv.tsv

    ```tsv
    sample-secret	sample value
    sample-pem-certificate	-----BEGIN PRIVATE KEY-----\n...\n-----END CERTIFICATE-----\n	application/x-pem-file
    sample-pfx-certificate	MIIV...	application/x-pkcs12
    ```

## DefaultAzureCredential

Simplifies authentication while developing apps that deploy to Azure by combining credentials used in Azure hosting environments with credentials used in local development. In production, it's better to use something else. See Usage guidance for DefaultAzureCredential.

Attempts to authenticate with each of these credentials, in the following order, stopping when one provides a token:

- [EnvironmentCredential](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.environmentcredential?view=azure-dotnet)
- [WorkloadIdentityCredential](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.workloadidentitycredential?view=azure-dotnet)
- [ManagedIdentityCredential](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.managedidentitycredential?view=azure-dotnet)
- [VisualStudioCredential](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.visualstudiocredential?view=azure-dotnet)
- [VisualStudioCodeCredential](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.visualstudiocodecredential?view=azure-dotnet)
- [AzureCliCredential](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.azureclicredential?view=azure-dotnet)
- [AzurePowerShellCredential](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.azurepowershellcredential?view=azure-dotnet)
- [AzureDeveloperCliCredential](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.azuredeveloperclicredential?view=azure-dotnet)
- [InteractiveBrowserCredential](https://learn.microsoft.com/en-us/dotnet/api/azure.identity.interactivebrowsercredential?view=azure-dotnet)
