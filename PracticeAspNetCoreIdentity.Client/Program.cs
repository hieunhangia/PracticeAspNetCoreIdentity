using Microsoft.AspNetCore.Components.Web;
using Microsoft.AspNetCore.Components.WebAssembly.Hosting;
using PracticeAspNetCoreIdentity.Client;

var builder = WebAssemblyHostBuilder.CreateDefault(args);
builder.RootComponents.Add<App>("#app");
builder.RootComponents.Add<HeadOutlet>("head::after");

builder.Services.AddScoped(_ => 
    new HttpClient { BaseAddress = new Uri(builder.HostEnvironment.BaseAddress) });
builder.Services.AddScoped<CookieHandler>();
builder.Services.AddHttpClient<WebApiHttpClient>(
        client => client.BaseAddress = new Uri(builder.Configuration["WebApiBaseUrl"]!))
    .AddHttpMessageHandler<CookieHandler>();

await builder.Build().RunAsync();