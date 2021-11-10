using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace KeyVaultTool {
    class Program {
        static string[] _args;
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
                { "-a", "Address" },
                { "-u", "ClientId" },
                { "--client-id", "ClientId" },
                { "-p", "ClientSecret" },
                { "--client-secret", "ClientSecret" },
                { "-m", "mode" },
                { "-f", "filter" },                
                { "-o", "file" }
            };
            cb.AddCommandLine(_args, switchMappings);
            IConfiguration config = cb.Build();
            var configPath = config["config"];
            if (File.Exists(configPath)) {
                cb.AddJsonFile(configPath);
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
