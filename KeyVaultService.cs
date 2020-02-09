using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Clients.ActiveDirectory;

namespace TestKeyVault
{
    public class KeyVaultService : BackgroundService
    {
        ILogger<KeyVaultService> _logger;
        KeyVaultOptions _options;
        private readonly IHostApplicationLifetime _appLifetime;
        private string _token;
        public KeyVaultService (
            ILogger<KeyVaultService> logger,
            IOptions<KeyVaultOptions> options,
            IHostApplicationLifetime appLifetime
            ){
            _logger = logger;
            _options = options.Value;
            _appLifetime = appLifetime;
        }
        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            try{
                switch(_options.Mode){
                    case OperationMode.Export:
                        await Export();
                        break;
                    case OperationMode.Import:
                        await Import();
                        break;
                }
            } catch(Exception ex) {
                _logger.LogError(ex, "ExecuteAsync");
                Console.Error.WriteLine(ex.ToString());
            }
            _appLifetime.StopApplication();            
        }

        async Task Export() {            
            var list = new List<SecretItem>();
            var kv = new KeyVaultClient(GetTokenAsync);
            for(var l = await kv.GetSecretsAsync(_options.Address); 
                l != null; 
                l = string.IsNullOrEmpty(l.NextPageLink) ? null: await kv.GetSecretsNextAsync(l.NextPageLink)) {
                list.AddRange(l);
            }
            Regex regex = new Regex(_options.Filter);
            var result = from l in list
                where regex.IsMatch(l.Identifier.Name) 
                select l;
            using(TextWriter writer = string.Compare(_options.File, "CON", true) == 0 ? Console.Out : File.CreateText(_options.File))
                foreach(var item in result) {                                        
                    var secret = await kv.GetSecretAsync(item.Id);
                    writer.WriteLine($"{secret.SecretIdentifier.Name}\t{secret.Value}");
                    if(!_options.ShowVersions)
                        continue;
                    var versions = new List<SecretItem>();
                    for(var v = await kv.GetSecretVersionsAsync(_options.Address, item.Identifier.Name); v != null; v = string.IsNullOrEmpty(v.NextPageLink) ? null: await kv.GetSecretVersionsNextAsync(v.NextPageLink)){
                        versions.AddRange(v);
                    }
                    foreach(var v in versions){
                        var temp = await kv.GetSecretAsync(v.Id);
                        var versionName = temp.Id.Substring(temp.Id.LastIndexOf('/') + 1);
                        var a = temp.Attributes;
                        Console.WriteLine($"\t{versionName}({a.Created}, {a.Updated}): {temp.Value}    ");
                    }
                }
        }
        async Task Import() {            
            var kv = new KeyVaultClient(GetTokenAsync);
            using(TextReader reader = string.Compare(_options.File, "CON", true) == 0 ? Console.In : File.OpenText(_options.File)){
                for(string line = await reader.ReadLineAsync(); line != null; line = await reader.ReadLineAsync()){
                    var items = line.Split('\t');
                    if(items.Length != 2)
                        continue;
                    var name = items[0];
                    var value = items[1];
                    Console.WriteLine(name);
                    try{
                        await kv.SetSecretAsync(_options.Address, name, value);     
                    } catch(Microsoft.Azure.KeyVault.Models.KeyVaultErrorException ex){
                        _logger.LogError(ex, "ExecuteAsync");
                        //Console.Error.WriteLine(ex.ToString());
                    }                    
                }
            }
        }
        async Task<string> GetTokenAsync(string authority, string resource, string scope){
            if(!string.IsNullOrEmpty(_token))
                return _token;
            if(string.IsNullOrEmpty(_options.ClientId) || string.IsNullOrEmpty(_options.ClientSecret)) {
                var tokenProvider = new AzureServiceTokenProvider();
                _token = await tokenProvider.KeyVaultTokenCallback(authority, resource, scope);
            } else {
                var adCredential = new ClientCredential(_options.ClientId, _options.ClientSecret);
                var authenticationContext = new AuthenticationContext(authority, null);
                _token =  (await authenticationContext.AcquireTokenAsync(resource, adCredential)).AccessToken;
            }
            return _token;
        }
    }
}
