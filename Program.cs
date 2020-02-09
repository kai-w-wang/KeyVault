using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace KeyVaultTool
{
    class Program
    {
        public static async Task Main(string[] args) {
            var host = Host.CreateDefaultBuilder(args)
                .ConfigureServices(ConfigureServices)
                .Build();
            await host.RunAsync();
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
