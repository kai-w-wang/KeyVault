using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace TestKeyVault
{
    class Program
    {
        public static async Task Main(string[] args) {
            // .NET Generic Host
            // https://docs.microsoft.com/en-us/aspnet/core/fundamentals/host/generic-host?view=aspnetcore-2.2
            var host = new HostBuilder()                
                .ConfigureAppConfiguration((hostContext, configBuilder) => {
                    // https://docs.microsoft.com/en-us/aspnet/core/fundamentals/configuration/?view=aspnetcore-2.2
                    // A typical sequence of configuration providers is:
                    // - Files(appsettings.json, appsettings.{ Environment}.json, where { Environment} is the app's current hosting environment)
                    // - Azure Key Vault
                    // - User secrets(Secret Manager)(Development environment only)
                    // - Environment variables
                    // - Command-line arguments
                    configBuilder.SetBasePath(AppDomain.CurrentDomain.BaseDirectory)
                    .AddJsonFile("appsettings.json", optional: true)
                    .AddJsonFile($"appsettings.{hostContext.HostingEnvironment.EnvironmentName}.json", optional: true)
                    .AddEnvironmentVariables()                    
                    .AddCommandLine(args);
                })
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
