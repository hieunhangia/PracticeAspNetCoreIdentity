using System.Net.Http.Json;

namespace PracticeAspNetCoreIdentity.Client;

public class WebApiHttpClient(HttpClient client)
{
    public async Task<HttpResponseMessage> LoginAsync(string email, string password, bool useCookie = true)
        => await client.PostAsJsonAsync(useCookie ? "login?useCookies=true" : "login", new { email, password });
    
    public async Task<HttpResponseMessage> RegisterAsync(string email, string password)
        => await client.PostAsJsonAsync("register", new { email, password });
}