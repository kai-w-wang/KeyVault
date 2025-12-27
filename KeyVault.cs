#!/usr/bin/dotnet run
/*
MIT License

Copyright (c) 2025 Kai Wang

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/
#:sdk Microsoft.NET.Sdk
#:package Azure.Extensions.AspNetCore.Configuration.Secrets@1.4.0
#:package Azure.Identity@1.17.1
#:package Azure.Security.KeyVault.Certificates@4.8.0
#:package Azure.Security.KeyVault.Keys@4.8.0
#:package Azure.Security.KeyVault.Secrets@4.8.0
// #:package Microsoft.Azure.Services.AppAuthentication@1.6.2
#:package Microsoft.Extensions.Configuration@10.0.1
#:package Microsoft.Extensions.Configuration.Commandline@10.0.1
#:package Microsoft.Extensions.Configuration.EnvironmentVariables@10.0.1
#:package Microsoft.Extensions.Configuration.Json@10.0.1
// #:package Microsoft.Extensions.Configuration.Xml@10.0.1
#:package Microsoft.Extensions.Configuration.Ini@10.0.1
#:package Microsoft.Extensions.DependencyInjection@10.0.1
#:package Microsoft.Extensions.Hosting@10.0.1
#:package Microsoft.Extensions.Options.ConfigurationExtensions@10.0.1
#:package Microsoft.Extensions.Logging@10.0.1
#:package Microsoft.Extensions.Logging.Abstractions@10.0.1
// #:package Microsoft.Extensions.Logging.Console@10.0.1
// #:package Microsoft.Extensions.Logging.Filter@1.1.2
#:package NetEscapades.Configuration.Yaml@3.1.0
#:package Microsoft.CodeAnalysis.CSharp@5.0.0
#:package Serilog@4.3.0
#:package Serilog.Extensions.Logging@10.0.0
#:package Serilog.Extensions.Hosting@10.0.0
#:package Serilog.Settings.Configuration@10.0.0
#:package Serilog.Sinks.Console@6.1.1

#:property EnableConfigurationBindingGenerator=true

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Data;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys;
using System.Text.Json.Serialization;
using Azure.Core;
using Serilog;
using ILogger = Microsoft.Extensions.Logging.ILogger;

namespace KeyVaultTool;

class Program {
    static string[] _args = null!;
    public static async Task Main(string[] args) {
        _args = args;
        IHost host = Host.CreateDefaultBuilder(args)
            .ConfigureAppConfiguration(ConfigureAppCongiuration)
            .ConfigureServices(ConfigureServices)
            .Build();
        await host.RunAsync();
    }
    static void ConfigureAppCongiuration(HostBuilderContext context, IConfigurationBuilder builder) {
        // var defaults = new Dictionary<string, string?> {
        //     ["Serilog:Using:0"] = "Serilog.Sinks.Console",
        //     ["Serilog:WriteTo:0:Name"] = "Console"
        // };
        // builder.AddInMemoryCollection(defaults);
        var switchMappings = new Dictionary<string, string>(){
                { "-c", "config" },
                { "-a", "address" },
                { "-t", "tenantId" },
                { "-u", "clientId" },
                { "-p", "clientSecret" },
                { "-m", "mode" },
                { "-f", "filter" },
                { "-o", "file" },
                { "-v", "showVersions" },
                { "--tenant-id", "tenantId" },
                { "--client-id", "clientId" },
                { "--content-type-filter", "contentTypeFileter" },
                { "--client-secret", "clientSecret" },
                { "--show-versions", "showVersions" },
            };
        builder.AddCommandLine(_args, switchMappings);
        IConfiguration config = builder.Build();
        var configPath = config["config"];
        if (File.Exists(configPath)) {
            var extName = Path.GetExtension(configPath);
            extName = extName.ToLower();
            switch (extName) {
                case ".json":
                    builder.AddJsonFile(configPath);
                    break;
                // case ".xml":
                //     cb.AddXmlFile(configPath);
                //     break;
                case ".ini":
                    builder.AddIniFile(configPath);
                    break;
                case ".yaml":
                    builder.AddYamlFile(configPath);
                    break;
                case ".yml":
                    builder.AddYamlFile(configPath);
                    break;
            }
        }
    }
    static void ConfigureServices(HostBuilderContext context, IServiceCollection services) {
        IConfiguration config = context.Configuration;
        services
            .Configure<HostOptions>(option => option.ShutdownTimeout = System.TimeSpan.FromSeconds(20))
            .Configure<ConsoleLifetimeOptions>(options => options.SuppressStatusMessages = true)
            .Configure<KeyVaultOptions>(config)
            .AddLogging(builder => {
                Log.Logger = new LoggerConfiguration()
                    .Enrich.FromLogContext()
                    .WriteTo.Console()
                    .CreateLogger();
                builder.ClearProviders() // Replace built-in Debug/Console providers with SeriLog.
                    .AddSerilog(dispose: true);

            })
            .AddHostedService<KeyVaultService>();
    }
}
[JsonConverter(typeof(JsonStringEnumConverter<OperationMode>))]
public enum OperationMode {
    Help,
    Export,
    Import,
    Copy
};
public class KeyVaultConnectionOptions {
    public string Address { set; get; } = null!;
    public string TenantId { set; get; } = null!;
    public string ClientId { set; get; } = null!;
    public string ClientSecret { set; get; } = null!;
    public StoreLocation StoreLocation { get; set; } = StoreLocation.CurrentUser;
    public string Thumbprint { set; get; } = null!;
    public IList<string> AdditionallyAllowedTenants { get; } = ["*"];
}
public class KeyVaultOptions : KeyVaultConnectionOptions {

    public OperationMode Mode { get; set; } = OperationMode.Export;
    public string File { get; set; } = "CON";
    public string Filter { get; set; } = ".*";
    public string Delimiter { get; set; } = "\t";
    public string Tags { get; set; } = ".*";
    public bool ShowVersions { get; set; }
    public bool Escape { get; set; }
    public string ContentTypeFilter { get; set; } = string.Empty;
    public string Scopes { get; set; } = "secrets, keys, certificates";
    public KeyVaultConnectionOptions? From { get; set; }
    public KeyVaultConnectionOptions? To { get; set; }
}
// [JsonSourceGenerationOptions(WriteIndented = true, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
// [JsonSerializable(typeof(KeyVaultConnectionOptions))]
// [JsonSerializable(typeof(KeyVaultOptions))]
// [JsonSerializable(typeof(OperationMode))]
// [JsonSerializable(typeof(bool))]
// [JsonSerializable(typeof(int))]
// internal partial class SourceGenerationContext : JsonSerializerContext { }

public class KeyVaultService : BackgroundService {
    ILogger _logger;
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
        if (string.IsNullOrWhiteSpace(_options.Address) && _options.From == null && _options.To == null)
            _options.Mode = OperationMode.Help;
        if (_options.Address != null && !_options.Address.Contains('.'))
            _options.Address = $"https://{_options.Address}.vault.azure.net/";
    }
    protected override async Task ExecuteAsync(CancellationToken stoppingToken) {
        try {
            switch (_options.Mode) {
                case OperationMode.Help:
                    await Help();
                    break;
                case OperationMode.Export:
                    await Export(stoppingToken);
                    break;
                case OperationMode.Import:
                    await Import(stoppingToken);
                    break;
                case OperationMode.Copy:
                    await Copy(stoppingToken);
                    break;
            }
        }
        catch (Exception ex) {
            _logger.LogError(ex, ex.Message);
        }
        _appLifetime.StopApplication();
    }
    async Task Import(CancellationToken stoppingToken) {
        using (TextReader reader = string.Compare(_options.File, "CON", true) == 0 ? Console.In : File.OpenText(_options.File)) {
            await Import(reader, stoppingToken);
        }
    }
    async Task Import(TextReader reader, CancellationToken stoppingToken) {
        var token = GetToken(_options.To ?? _options);
        var uri = new Uri(_options.To?.Address ?? _options.Address);
        var scopes = _options.Scopes.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var secretClient = scopes.Contains("secrets") ? new SecretClient(uri, token) : null;
        var keyClient = scopes.Contains("keys") ? new KeyClient(uri, token) : null;
        var certificateClient = scopes.Contains("certificates") ? new CertificateClient(uri, token) : null;
        for (var line = await reader.ReadLineAsync(); line != null; line = await reader.ReadLineAsync()) {
            var items = line.Split('\t');
            if (items.Length < 2)
                continue;
            var name = items[0];
            var value = items[1];
            if (_options.Escape)
                value = Unescape(value);
            _logger.LogInformation("Import: {0}", name);
            try {
                var contentType = items.Length > 2 ? items[2] : null;
                if (contentType == null) {
                    if (secretClient != null)
                        await secretClient.SetSecretAsync(new KeyVaultSecret(name, value), stoppingToken);
                } else {
                    switch (contentType.ToLower()) {
                        case "application/x-pkcs12":
                            if (certificateClient != null)
                                await certificateClient.ImportCertificateAsync(new ImportCertificateOptions(name, Convert.FromBase64String(value)), stoppingToken);
                            break;
                        case "application/x-pem-file":
                            if (certificateClient != null)
                                await certificateClient.ImportCertificateAsync(new ImportCertificateOptions(name, Encoding.UTF8.GetBytes(value)), stoppingToken);
                            break;
                        case "application/x-key-backup":
                            if (keyClient != null)
                                await keyClient.RestoreKeyBackupAsync(Convert.FromBase64String(value), stoppingToken);
                            break;
                        default:
                            if (secretClient != null)
                                await secretClient.SetSecretAsync(new KeyVaultSecret(name, value) { Properties = { ContentType = contentType } }, stoppingToken);
                            break;
                    }
                }
            }
            catch (Exception ex) {
                _logger.LogError(ex, "ExecuteAsync");
                //Console.Error.WriteLine(ex.ToString());
            }
        }
    }
    async Task Export(CancellationToken stoppingToken) {
        bool toConsole = string.Compare(_options.File, "CON", true) == 0;
        using TextWriter writer = toConsole ? Console.Out : File.CreateText(_options.File);
        await Export(writer, stoppingToken);
    }
    async Task Export(TextWriter writer, CancellationToken stoppingToken) {
        var uri = new Uri(_options.From?.Address ?? _options.Address);
        var token = GetToken(_options.From ?? _options);
        var scopes = _options.Scopes.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (scopes.Contains("secrets")) {
            _logger.LogDebug("Exporting secrets...");
            await ExportSecrets(uri, token, writer, stoppingToken);
        }
        if (scopes.Contains("keys")) {
            _logger.LogDebug("Exporting keys...");
            await ExportKeys(uri, token, writer, stoppingToken);
        }
        // if (scopes.Contains("certificates"))
        //     await ExportCertificates(writer, stoppingToken);
    }
    async Task ExportSecrets(Uri uri, TokenCredential token, TextWriter writer, CancellationToken stoppingToken) {
        List<SecretProperties> list = [];
        var secretClient = new SecretClient(uri, token);
        AsyncPageable<SecretProperties> allSecrets = secretClient.GetPropertiesOfSecretsAsync(stoppingToken);
        await foreach (SecretProperties secret in allSecrets) {
            // Getting a disabled secret will fail, so skip disabled secrets.
            if (!secret.Enabled.GetValueOrDefault())
                continue;
            list.Add(secret);
        }
        bool emptyContentTypeFilter = string.IsNullOrEmpty(_options.ContentTypeFilter);
        IEnumerable<SecretProperties> result = emptyContentTypeFilter ?
            list.Where(l => Regex.IsMatch(l.Name, _options.Filter) && string.IsNullOrEmpty(l.ContentType))
            : list.Where(l => Regex.IsMatch(l.Name, _options.Filter) && Regex.IsMatch(l.ContentType ?? string.Empty, _options.ContentTypeFilter));
        foreach (SecretProperties item in result) {
            KeyVaultSecret secret = await secretClient.GetSecretAsync(item.Name);
            string secretValue = secret.Value;
            if (_options.Escape)
                secretValue = Escape(secretValue);

            List<string> valueList = [secret.Name, secretValue];
            if (!string.IsNullOrWhiteSpace(secret.Properties.ContentType))
                valueList.Add(secret.Properties.ContentType);
            string line = string.Join(_options.Delimiter, valueList);
            writer.WriteLine(line);
            if (!_options.ShowVersions)
                continue;
            List<KeyVaultSecret> versions = [];
            await foreach (SecretProperties v in secretClient.GetPropertiesOfSecretVersionsAsync(secret.Name)) {
                // Secret versions may also be disabled if compromised and new versions generated, so skip disabled versions, too.
                if (!v.Enabled.GetValueOrDefault()) {
                    continue;
                }
                KeyVaultSecret versionValue = await secretClient.GetSecretAsync(v.Name, v.Version);
                versions.Add(versionValue);
            }
            foreach (KeyVaultSecret? v in versions.OrderBy(v => v.Properties.UpdatedOn)) {
                var id = v.Id.ToString();
                var versionName = id.Substring(id.LastIndexOf('/') + 1);
                secretValue = v.Value;
                if (_options.Escape)
                    secretValue = secretValue.Replace("\n", "");
                writer.WriteLine($"  {v.Properties.UpdatedOn:O}{versionName}\t{secretValue}");
            }
        }
    }
    async Task ExportKeys(Uri uri, TokenCredential token, TextWriter writer, CancellationToken stoppingToken) {
        var client = new KeyClient(uri, token);
        AsyncPageable<KeyProperties> allKeys = client.GetPropertiesOfKeysAsync();
        var keyDictionary = new Dictionary<string, byte[]>();
        await foreach (KeyProperties key in allKeys) {
            if (key.Managed)
                continue;
            Response<byte[]> backupBytes = await client.BackupKeyAsync(key.Name);
            keyDictionary[key.Name] = backupBytes.Value;
        }
        foreach (KeyValuePair<string, byte[]> entry in keyDictionary) {
            string[] valueList = [entry.Key, Convert.ToBase64String(entry.Value), "application/x-key-backup"];
            string line = string.Join(_options.Delimiter, valueList);
            writer.WriteLine(line);
        }
    }
    // async Task ExportCertificates(TextWriter writer, CancellationToken stoppingToken) {
    //     // var client = new CertificateClient(new Uri(_options.DestinationAddress ?? _options.Address), GetToken(_options.SourceAddress ?? _options.Address));
    //     // AsyncPageable<CertificateProperties> allCertificates = client.GetPropertiesOfCertificatesAsync();
    //     // await foreach (CertificateProperties certificateProperties in allCertificates) {
    //     //     // Console.WriteLine(certificateProperties.Name);
    //     //     var cert = await client.GetCertificateAsync(certificateProperties.Name, cancellationToken: stoppingToken);
    //     // }
    //     await Task.CompletedTask;
    // }
    async Task Copy(CancellationToken stoppingToken) {
        _logger.LogInformation("Copy '{0}' from {1} to {2}",
            _options.Scopes,
            _options.From?.Address ?? _options.Address,
            _options.To?.Address ?? _options.Address
            );
        using (var stream = new MemoryStream()) {
            using (StreamWriter writer = new(stream, Encoding.UTF8, 4096, true)) {
                await Export(writer, stoppingToken);
            }
            stream.Position = 0;
            using (StreamReader reader = new(stream, Encoding.UTF8, false, 4096, true)) {
                await Import(reader, stoppingToken);
            }
        }
    }
    private TokenCredential GetToken(KeyVaultConnectionOptions options) {
        if (!string.IsNullOrEmpty(options.TenantId)
            && !string.IsNullOrEmpty(options.ClientId)
            && !string.IsNullOrEmpty(options.Thumbprint)) {
            string thumbprint = options.Thumbprint.Trim();
            using X509Store store = new(StoreName.My, options.StoreLocation);
            store.Open(OpenFlags.ReadOnly);
            // Find the certificate that matches the thumbprint.
            X509Certificate2Collection certCollection = store.Certificates.Find(
                X509FindType.FindByThumbprint, thumbprint, false);
            if (certCollection != null) {
                X509Certificate2? certificate = certCollection.FirstOrDefault();
                if (certificate != null) {
                    ClientCertificateCredentialOptions certOptions = new() { AuthorityHost = GetAuthorityHost(options.Address) };
                    foreach (var tenant in _options.AdditionallyAllowedTenants)
                        if (!certOptions.AdditionallyAllowedTenants.Contains(tenant))
                            certOptions.AdditionallyAllowedTenants.Add(tenant);
                    return new ClientCertificateCredential(_options.TenantId, _options.ClientId, certificate, certOptions);
                }
            }
        }

        if (!string.IsNullOrEmpty(_options.TenantId) && !string.IsNullOrEmpty(_options.ClientId) && !string.IsNullOrEmpty(_options.ClientSecret)) {
            ClientSecretCredentialOptions o = new() {
                AuthorityHost = GetAuthorityHost(options.Address)
            };
            foreach (string tenant in _options.AdditionallyAllowedTenants)
                if (!options.AdditionallyAllowedTenants.Contains(tenant))
                    o.AdditionallyAllowedTenants.Add(tenant);
            return new ClientSecretCredential(_options.TenantId, _options.ClientId, _options.ClientSecret, o);
        }

        var defaultOptions = new DefaultAzureCredentialOptions() {
            AuthorityHost = GetAuthorityHost(options.Address),
            ManagedIdentityClientId = _options.ClientId
        };
        foreach (string tenant in _options.AdditionallyAllowedTenants)
            if (!defaultOptions.AdditionallyAllowedTenants.Contains(tenant))
                defaultOptions.AdditionallyAllowedTenants.Add(tenant);
        return new DefaultAzureCredential(defaultOptions);
    }
    private static Uri GetAuthorityHost(string uri) => GetAuthorityHost(new Uri(uri));
    private static Uri GetAuthorityHost(Uri kvAddress) {
        string host = kvAddress.Host;
        string suffix = host.Substring(host.IndexOf('.') + 1);
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
        StringBuilder cb = new(4096);
        cb.AppendLine($"Version: {typeof(Program).Assembly.GetName().Version}, Author: Kai Wang");
        cb.AppendLine();
        cb.AppendLine("Options:");
        cb.AppendLine("  -a, --address        Azure Key Vault addresss.");
        cb.AppendLine("  -c, --config         Config file (json|ini|yaml|yml)");
        cb.AppendLine("  -f, --filter         Filter rules regular expression");
        cb.AppendLine("  -m, --mode           Import/Export. Default: Export");
        cb.AppendLine("  -o, --file           File path to be used for import or export");
        cb.AppendLine("  -p, --client-secret  Client secret");
        cb.AppendLine("  -s, --scopes         Scopes. Default: secrets,keys,certificates");
        cb.AppendLine("  -t, --tenant-id      Tenant id");
        cb.AppendLine("  -u, --client-id      Client id");
        cb.AppendLine("  -v, --show-versions  Show versions.  Default: false. Format: {a.Updated.Value:O}{versionName}\t{value}");
        cb.AppendLine();
        cb.AppendLine("Samples:");
        cb.AppendLine("  KeyVault --address https://sample.vault.azure.net/");
        cb.AppendLine("  KeyVault --address https://sample.vault.azure.net/ --filter .*Vault.*");
        cb.AppendLine("  KeyVault --address https://sample.vault.azure.net/ --tenant-id {tenant} --client-id {guid} --client-secret {secret} --mode import --file output.txt");
        cb.AppendLine("  KeyVault --address https://sample.vault.azure.net/ --tenant-id {tenant} --client-id {guid} --client-secret {secret} --mode export --file output.txt");
        cb.AppendLine("  KeyVault --config config.yml");
        _logger.LogInformation(cb.ToString());
        await Task.CompletedTask;
    }
}

