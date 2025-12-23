using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;

namespace PracticeAspNetCoreIdentity.Client;

public abstract class Program
{
    public static async Task Main(string[] args)
    {
        var builder = WebAssemblyHostBuilder.CreateDefault(args);
        builder.RootComponents.Add<App>("#app");
        builder.RootComponents.Add<HeadOutlet>("head::after");

        builder.Services.AddScoped<CookieHandler>();
        builder.Services.AddScoped(sp =>
        {
            var cookieHandler = sp.GetRequiredService<CookieHandler>();
            cookieHandler.InnerHandler = new HttpClientHandler();
            return new HttpClient(cookieHandler) {
                BaseAddress = new Uri(builder.Configuration["WebApiBaseUrl"]!)
            };
        });

        await builder.Build().RunAsync();
    }
}