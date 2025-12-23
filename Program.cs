using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace KeyVaultTool {
    class Program {
        static string[] _args = null!;
        public static async Task Main(string[] args) {
            _args = args;
            var host = Host.CreateDefaultBuilder(args)
                .ConfigureAppConfiguration(ConfigureAppCongiuration)
                .ConfigureServices(ConfigureServices)
                .Build();
            await host.RunAsync();
        }
        static void ConfigureAppCongiuration(HostBuilderContext context, IConfigurationBuilder cb) {
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
            cb.AddCommandLine(_args, switchMappings);
            IConfiguration config = cb.Build();
            var configPath = config["config"];
            if (File.Exists(configPath)) {
                var extName = Path.GetExtension(configPath);
                extName = extName.ToLower();
                switch(extName) {
                    case ".json":
                        cb.AddJsonFile(configPath);
                        break;
                    case ".xml":
                        cb.AddXmlFile(configPath);
                        break;
                    case ".ini":
                        cb.AddIniFile(configPath);
                        break;
                    case ".yaml":
                        cb.AddYamlFile(configPath);
                        break;
                    case ".yml":
                        cb.AddYamlFile(configPath);
                        break;
                }
                
            }
        }
        static void ConfigureServices(HostBuilderContext context, IServiceCollection services) {
            var config = context.Configuration;
            services
                .Configure<HostOptions>(option => option.ShutdownTimeout = System.TimeSpan.FromSeconds(20))
                .Configure<ConsoleLifetimeOptions>(options => options.SuppressStatusMessages = true)
                .Configure<KeyVaultOptions>(config)
                .AddHostedService<KeyVaultService>();
        }
    }
}
