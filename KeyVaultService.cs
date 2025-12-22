using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlTypes;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Unicode;
using System.Threading;
using System.Threading.Tasks;
using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Secrets;

using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace KeyVaultTool {
    public class KeyVaultService : BackgroundService {
        ILogger<KeyVaultService> _logger;
        KeyVaultOptions _options;
        private readonly IHostApplicationLifetime _appLifetime;
        public KeyVaultService(
            ILogger<KeyVaultService> logger,
            IOptions<KeyVaultOptions> options,
            IHostApplicationLifetime appLifetime
            ) {
            _logger = logger;
            _options = options.Value;
            _appLifetime = appLifetime;
            if (string.IsNullOrWhiteSpace(_options.Address))
                _options.Mode = OperationMode.Help;
            if (_options.Address != null && !_options.Address.Contains('.'))
                _options.Address = $"https://{_options.Address}.vault.azure.net/";
        }
        protected override async Task ExecuteAsync(CancellationToken stoppingToken) {
            try {
                switch (_options.Mode) {
                    case OperationMode.Export:
                        await Export(stoppingToken);
                        break;
                    case OperationMode.Import:
                        await Import(stoppingToken);
                        break;
                    case OperationMode.Help:
                        await Help();
                        break;
                }
            }
            catch (Exception ex) {
                _logger.LogError(ex, ex.Message);
            }
            _appLifetime.StopApplication();
        }
        async Task Import(CancellationToken stoppingToken) {
            var kv = new SecretClient(new Uri(_options.Address), GetToken());
            using (TextReader reader = string.Compare(_options.File, "CON", true) == 0 ? Console.In : File.OpenText(_options.File)) {
                for (var line = await reader.ReadLineAsync(); line != null; line = await reader.ReadLineAsync()) {
                    var items = line.Split('\t');
                    if (items.Length < 2)
                        continue;
                    var name = items[0];
                    var value = items[1];
                    if (_options.Escape)
                        value = Unescape(value);
                    Console.WriteLine(name);
                    try {
                        var contentType = items.Length > 2 ? items[2] : null;
                        if (contentType == null)
                            await kv.SetSecretAsync(new KeyVaultSecret(name, value), stoppingToken);
                        else
                            switch (contentType.ToLower()) {
                                case "application/x-pkcs12":
                                    await ImportPfxCertificateAsync(name, value, stoppingToken);
                                    break;
                                case "application/x-pem-file":
                                    await ImportPemCertificateAsync(name, value, stoppingToken);
                                    break;
                                case "application/x-key-backup":
                                    await ImportKeyBackupAsync(name, value, stoppingToken);
                                    break;
                                default:
                                    await kv.SetSecretAsync(new KeyVaultSecret(name, value) { Properties = { ContentType = contentType } }, stoppingToken);
                                    break;
                            }
                    }
                    catch (Exception ex) {
                        _logger.LogError(ex, "ExecuteAsync");
                        //Console.Error.WriteLine(ex.ToString());
                    }
                }
            }
        }
        async Task ImportPfxCertificateAsync(string name, string base64Value, CancellationToken stoppingToken = default) {
            var client = new CertificateClient(new Uri(_options.Address), GetToken());
            ImportCertificateOptions importOptions = new ImportCertificateOptions(name, Convert.FromBase64String(base64Value));
            await client.ImportCertificateAsync(importOptions, stoppingToken);
        }
        async Task ImportPemCertificateAsync(string name, string value, CancellationToken stoppingToken = default) {
            var client = new CertificateClient(new Uri(_options.Address), GetToken());
            ImportCertificateOptions importOptions = new ImportCertificateOptions(name, Encoding.UTF8.GetBytes(value));
            await client.ImportCertificateAsync(importOptions, stoppingToken);
        }
        async Task ImportKeyBackupAsync(string name, string value, CancellationToken stoppingToken = default) {
            KeyClient client = new KeyClient(new Uri(_options.Address), GetToken());
            await client.RestoreKeyBackupAsync(Convert.FromBase64String(value), stoppingToken);
        }
        async Task Export(CancellationToken stoppingToken) {
            if (_options.scopes.Contains("secrets"))
                await ExportSecrets(stoppingToken);
            if (_options.scopes.Contains("keys"))
                await ExportKeys(stoppingToken);
            if (_options.scopes.Contains("certificates"))
                await ExportCertificates(stoppingToken);
        }
        async Task ExportSecrets(CancellationToken stoppingToken) {
            var list = new List<Azure.Security.KeyVault.Secrets.SecretProperties>();
            var secretClient = new SecretClient(new Uri(_options.Address), GetToken());
            var allSecrets = secretClient.GetPropertiesOfSecretsAsync(stoppingToken);
            await foreach (var secret in allSecrets) {
                // Getting a disabled secret will fail, so skip disabled secrets.
                if (!secret.Enabled.GetValueOrDefault())
                    continue;
                list.Add(secret);
            }
            var emptyContentTypeFilter = string.IsNullOrEmpty(_options.ContentTypeFilter);
            var result = emptyContentTypeFilter ?
                list.Where(l => Regex.IsMatch(l.Name, _options.Filter) && string.IsNullOrEmpty(l.ContentType))
                : list.Where(l => Regex.IsMatch(l.Name, _options.Filter) && Regex.IsMatch(l.ContentType ?? string.Empty, _options.ContentTypeFilter));
            using (TextWriter writer = string.Compare(_options.File, "CON", true) == 0 ? Console.Out : File.CreateText(_options.File))
                foreach (var item in result) {
                    KeyVaultSecret secret = await secretClient.GetSecretAsync(item.Name);
                    //var secret = await kv.GetSecretAsync(item.Id, stoppingToken);
                    var secretValue = secret.Value;
                    if (_options.Escape)
                        secretValue = Escape(secretValue);

                    var valueList = new List<string>(){
                        secret.Name,
                        secretValue
                    };
                    if (!string.IsNullOrWhiteSpace(secret.Properties.ContentType))
                        valueList.Add(secret.Properties.ContentType);
                    // if (item.Tags != null)
                    //     valueList.AddRange(item.Tags.Values);
                    var line = string.Join(_options.Delimiter, valueList);
                    writer.WriteLine(line);
                    if (!_options.ShowVersions)
                        continue;
                    var versions = new List<KeyVaultSecret>();
                    await foreach (var v in secretClient.GetPropertiesOfSecretVersionsAsync(secret.Name)) {
                        // Secret versions may also be disabled if compromised and new versions generated, so skip disabled versions, too.
                        if (!v.Enabled.GetValueOrDefault()) {
                            continue;
                        }
                        KeyVaultSecret versionValue = await secretClient.GetSecretAsync(v.Name, v.Version);
                        versions.Add(versionValue);
                    }
                    foreach (var v in versions.OrderBy(v => v.Properties.UpdatedOn)) {
                        var id = v.Id.ToString();
                        var versionName = id.Substring(id.LastIndexOf('/') + 1);
                        secretValue = v.Value;
                        if (_options.Escape)
                            secretValue = secretValue.Replace("\n", "");
                        writer.WriteLine($"  {v.Properties.UpdatedOn:O}{versionName}\t{secretValue}");
                    }
                }
        }
        async Task ExportKeys(CancellationToken stoppingToken) {
            KeyClient client = new KeyClient(new Uri(_options.Address), GetToken());
            AsyncPageable<KeyProperties> allKeys = client.GetPropertiesOfKeysAsync();
            var keyDictionary = new Dictionary<string, byte[]>();
            await foreach (KeyProperties key in allKeys) {
                Response<byte[]> backupBytes = await client.BackupKeyAsync(key.Name);
                keyDictionary[key.Name] = backupBytes.Value;
            }
            using (TextWriter writer = string.Compare(_options.File, "CON", true) == 0 ? Console.Out : File.CreateText(_options.File)) {
                foreach (var entry in keyDictionary) {
                    string[] valueList = [entry.Key,  Convert.ToBase64String(entry.Value), "application/x-key-backup"];
                    var line = string.Join(_options.Delimiter, valueList);
                    writer.WriteLine(line);
                }
            }
            await Task.CompletedTask;
        }
        async Task ExportCertificates(CancellationToken stoppingToken) {
            // var client = new CertificateClient(new Uri(_options.Address), GetToken());
            // AsyncPageable<CertificateProperties> allCertificates = client.GetPropertiesOfCertificatesAsync();
            // await foreach (CertificateProperties certificateProperties in allCertificates) {
            //     // Console.WriteLine(certificateProperties.Name);
            //     var cert = await client.GetCertificateAsync(certificateProperties.Name, cancellationToken: stoppingToken);
            // }
            await Task.CompletedTask;
        }
        private Azure.Core.TokenCredential GetToken() {
            if (!string.IsNullOrEmpty(_options.TenantId)
                && !string.IsNullOrEmpty(_options.ClientId)
                && !string.IsNullOrEmpty(_options.Thumbprint)) {
                var thumbprint = _options.Thumbprint.Trim();
                using var store = new X509Store(StoreName.My, _options.StoreLocation);
                store.Open(OpenFlags.ReadOnly);
                // Find the certificate that matches the thumbprint.
                var certCollection = store.Certificates.Find(
                    X509FindType.FindByThumbprint, thumbprint, false);
                if (certCollection != null) {
                    var certificate = certCollection.FirstOrDefault();
                    if (certificate != null) {
                        ClientCertificateCredentialOptions certOptions = new ClientCertificateCredentialOptions {
                            AuthorityHost = GetAuthorityHost(_options.Address)
                        };
                        foreach (var tenant in _options.AdditionallyAllowedTenants)
                            if (!certOptions.AdditionallyAllowedTenants.Contains(tenant))
                                certOptions.AdditionallyAllowedTenants.Add(tenant);
                        return new ClientCertificateCredential(_options.TenantId, _options.ClientId, certificate, certOptions);
                    }
                }
            }

            if (!string.IsNullOrEmpty(_options.TenantId)
                && !string.IsNullOrEmpty(_options.ClientId)
                && !string.IsNullOrEmpty(_options.ClientSecret
                )) {
                ClientSecretCredentialOptions options = new ClientSecretCredentialOptions();
                options.AuthorityHost = GetAuthorityHost(_options.Address);
                foreach (var tenant in _options.AdditionallyAllowedTenants)
                    if (!options.AdditionallyAllowedTenants.Contains(tenant))
                        options.AdditionallyAllowedTenants.Add(tenant);
                return new ClientSecretCredential(_options.TenantId, _options.ClientId, _options.ClientSecret, options);
            }

            var defaultOptions = new DefaultAzureCredentialOptions() {
                AuthorityHost = GetAuthorityHost(_options.Address),
                ManagedIdentityClientId = _options.ClientId
            };
            foreach (var tenant in _options.AdditionallyAllowedTenants)
                if (!defaultOptions.AdditionallyAllowedTenants.Contains(tenant))
                    defaultOptions.AdditionallyAllowedTenants.Add(tenant);
            return new DefaultAzureCredential(defaultOptions);
        }
        private static Uri GetAuthorityHost(string uri) => GetAuthorityHost(new Uri(uri));
        private static Uri GetAuthorityHost(Uri kvAddress) {
            var host = kvAddress.Host;
            var suffix = host.Substring(host.IndexOf('.') + 1);
            return suffix switch {
                "vault.azure.cn" => AzureAuthorityHosts.AzureChina,
                "vault.azure.net" => AzureAuthorityHosts.AzurePublicCloud,
                _ => AzureAuthorityHosts.AzurePublicCloud
            };
        }
        // private static string ToLiteral(string input) {
        //     using (var writer = new StringWriter()) {
        //         using (var provider = CodeDomProvider.CreateProvider("CSharp")) {
        //             provider.GenerateCodeFromExpression(new CodePrimitiveExpression(input), writer, null);
        //             return writer.ToString();
        //         }
        //     }
        // }
        private static string Escape(string valueTextForCompiler) {
            return Microsoft.CodeAnalysis.CSharp.SymbolDisplay.FormatLiteral(valueTextForCompiler, false);
        }
        private static string Unescape(string str) {
            return Regex.Unescape(str);
        }
        async Task Help() {
            StringBuilder cb = new StringBuilder(4096);
            cb.AppendLine("Author: Kai Wang");
            cb.AppendLine();
            cb.AppendLine("Options:");
            cb.AppendLine("  -a, --address        Azure Key Vault addresss.");
            cb.AppendLine("  -c, --config         Config file");
            cb.AppendLine("  -t, --tenant-id      Tenant id");
            cb.AppendLine("  -u, --client-id      Client id");
            cb.AppendLine("  -p, --client-secret  Client secret");
            cb.AppendLine("  -m, --mode           Import/Export. Default: Export");
            cb.AppendLine("  -o, --file           File path to be used for import or export");
            cb.AppendLine("  -s, --scopes         Scopes. Default: secrets,keys,certificates");
            cb.AppendLine("  -f, --filter         Filter rules regular expression");
            cb.AppendLine("  -v, --show-versions  Show versions.  Default: false. Format: {a.Updated.Value:O}{versionName}\t{value}");
            cb.AppendLine();
            cb.AppendLine("Samples:");
            cb.AppendLine("  --address https://sample.vault.azure.net/");
            cb.AppendLine("  --address https://sample.vault.azure.cn/ --filter .*Vault.*");
            cb.AppendLine("  --address https://sample.vault.azure.cn/ --tenant-id {tenant} --client-id {guid} --client-secret {secret}");
            cb.AppendLine("  --address https://sample.vault.azure.cn/ --tenant-id {tenant} --client-id {guid} --client-secret {secret} --mode import --file output.txt");
            cb.AppendLine("  --address https://sample.vault.azure.cn/ --tenant-id {tenant} --client-id {guid} --client-secret {secret} --mode export --file output.txt");
            _logger.LogInformation(cb.ToString());
            await Task.CompletedTask;
        }
    }
}
