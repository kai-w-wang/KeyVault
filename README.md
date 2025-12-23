# KeyVault

Azure Key Vault Tool to import/export secrets, keys and certificates.

This repo requires .NET SDK version 10 or later.

## Build

```cmd
dotnet publish KeyVault.csproj -c Release -p:AssemblyVersion=1.0.0.0 -p:Version=1.0.0.0 -p:PublishSingleFile=true -r win-x64 --self-contained false -o c:\tools
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
    keyvault --Address https://{name}.vault.azure.cn/
    REM Export content into file instead of console output (stdout)
    keyvault --address https://{name}.vault.azure.net --filter .*Vault.*  --file output.txt
    ```

1. Export key vault content with SPN:

    ```cmd
    keyvault --Address https://{name}.vault.azure.cn/ --client-id {guid} --client-secret "****"
    ```

1. Import from file into Key Vault:

    ```cmd
    keyvault --Address "https://{name}.vault.azure.cn/" --client-id {guid} --client-secret "****" --mode Import --file kv.txt
    ```

1. Execute KeyVaultTool with configuration file:

    ```cmd
    keyvault --config config.yml
    ```

    Sample config.yml

    ```yaml
    Address: https://{name}.vault.azure.cn/
    TenantId: {TenantId}
    # ClientId: 
    # ClientSecret: 
    # Thumbprint: 
    Mode: Export
    File: kv.txt
    ShowVersions: false
    ContentTypeFilter: ".*"
    Escape: true
    ```
