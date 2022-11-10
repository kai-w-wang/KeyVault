using System;
using System.Collections.Generic;
using System.Data;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Azure.Identity;
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
            if (string.IsNullOrWhiteSpace(_options?.Address))
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
                for (string line = await reader.ReadLineAsync(); line != null; line = await reader.ReadLineAsync()) {
                    var items = line.Split('\t');
                    if (items.Length != 2)
                        continue;
                    var name = items[0];
                    var value = items[1];
                    Console.WriteLine(name);
                    try {
                        await kv.SetSecretAsync(name, value, stoppingToken);
                    }
                    catch (Exception ex) {
                        _logger.LogError(ex, "ExecuteAsync");
                        //Console.Error.WriteLine(ex.ToString());
                    }
                }
            }
        }
        async Task Export(CancellationToken stoppingToken) {
            var list = new List<Azure.Security.KeyVault.Secrets.SecretProperties>();
            var kv = new SecretClient(new Uri(_options.Address), GetToken());
            var allSecrets = kv.GetPropertiesOfSecretsAsync(stoppingToken);
            await foreach (var secret in allSecrets) {
                // Getting a disabled secret will fail, so skip disabled secrets.
                if (!secret.Enabled.GetValueOrDefault())
                    continue;
                list.Add(secret);
            }
            var emptyContentTypeFilter = string.IsNullOrEmpty(_options.ContentTypeFilter);
            var result = emptyContentTypeFilter ?
                list.Where(l => Regex.IsMatch(l.Name, _options.Filter) && string.IsNullOrEmpty(l.ContentType))
                : list.Where(l => Regex.IsMatch(l.Name, _options.Filter) && Regex.IsMatch(l.ContentType, _options.ContentTypeFilter));
            using (TextWriter writer = string.Compare(_options.File, "CON", true) == 0 ? Console.Out : File.CreateText(_options.File))
                foreach (var item in result) {
                    KeyVaultSecret secret = await kv.GetSecretAsync(item.Name);
                    //var secret = await kv.GetSecretAsync(item.Id, stoppingToken);
                    var valueList = new List<string>(){
                        secret.Name,
                        secret.Value
                    };
                    // if (item.Tags != null)
                    //     valueList.AddRange(item.Tags.Values);
                    var line = string.Join(_options.Delimiter, valueList);
                    writer.WriteLine(line);
                    if (!_options.ShowVersions)
                        continue;
                    var versions = new List<KeyVaultSecret>();
                    await foreach (var v in kv.GetPropertiesOfSecretVersionsAsync(secret.Name)) {
                        // Secret versions may also be disabled if compromised and new versions generated, so skip disabled versions, too.
                        if (!v.Enabled.GetValueOrDefault()) {
                            continue;
                        }
                        KeyVaultSecret versionValue = await kv.GetSecretAsync(v.Name, v.Version);
                        versions.Add(versionValue);
                    }
                    foreach (var v in versions.OrderBy(v => v.Properties.UpdatedOn)) {
                        var id = v.Id.ToString();
                        var versionName = id.Substring(id.LastIndexOf('/') + 1);
                        writer.WriteLine($"  {v.Properties.UpdatedOn:O}{versionName}\t{v.Value}");
                    }
                }
        }
        private Azure.Core.TokenCredential GetToken() {
            if (string.IsNullOrEmpty(_options.ClientId) || string.IsNullOrEmpty(_options.ClientSecret)) {
                DefaultAzureCredentialOptions options = new DefaultAzureCredentialOptions() {
                    AuthorityHost = GetAuthorityHost(),
                    ManagedIdentityClientId = _options.ClientId
                };
                return new DefaultAzureCredential(options);
            } else {
                ClientSecretCredentialOptions options = new ClientSecretCredentialOptions();
                options.AuthorityHost = GetAuthorityHost();
                return new ClientSecretCredential(_options.TenantId, _options.ClientId, _options.ClientSecret, options);
            }
        }
        private Uri GetAuthorityHost() {
            Uri kvAddress = new Uri(_options.Address);
            var str = _options.Address;
            var host = kvAddress.Host;
            var suffix = host.Substring(host.IndexOf('.') + 1);
            switch (suffix) {
                case "vault.azure.cn":
                    return AzureAuthorityHosts.AzureChina;
                case "vault.azure.net":
                    return AzureAuthorityHosts.AzurePublicCloud;
                default:
                    return AzureAuthorityHosts.AzurePublicCloud;
            }
        }
        async Task Help() {
            StringBuilder cb = new StringBuilder(4096);
            cb.AppendLine("  -a, --address        Azure Key Vault addresss.");
            cb.AppendLine("  -c, --config         Config file");
            cb.AppendLine("  -t, --tenant-id      Tenant id");
            cb.AppendLine("  -u, --client-id      Client id");
            cb.AppendLine("  -p, --client-secret  Client secret");
            cb.AppendLine("  -m, --mode           Import/Export. Default: Export");
            cb.AppendLine("  -o, --file           File path to be used for import or export.");
            cb.AppendLine("  -f, --filter         Filter rules regular expressioin.");
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
