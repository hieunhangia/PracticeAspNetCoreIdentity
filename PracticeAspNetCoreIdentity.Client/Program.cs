using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using PracticeAspNetCoreIdentity.Client;

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