using System.Net.Http.Json;
using PracticeAspNetCoreIdentity.Shared.Models;

namespace PracticeAspNetCoreIdentity.Client;

public class WebApiHttpClient(HttpClient client)
{
    public async Task<HttpResponseMessage> CookieLoginAsync(string email, string password)
        => await client.PostAsJsonAsync("login?useCookies=true", new { email, password });

    public async Task<HttpResponseMessage> RegisterAsync(string email, string password)
        => await client.PostAsJsonAsync("register", new { email, password });

    public async Task<HttpResponseMessage> GetUserInfoAsync()
        => await client.GetAsync("manage/info");

    public async Task CookieLogoutAsync()
        => await client.PostAsync("cookie-logout", null);

    public async Task<HttpResponseMessage> GetUserRolesAsync()
        => await client.GetAsync("manage/roles");
    
    public async Task<HttpResponseMessage> GetAllNotesAsync()
        => await client.GetAsync("notes");
    
    public async Task<HttpResponseMessage> GetNoteByIdAsync(Guid id)
        => await client.GetAsync($"notes/{id}");
    
    public async Task<HttpResponseMessage> AddNoteAsync(CreateUpdateUserNoteRequest request)
        => await client.PostAsJsonAsync("notes", request);
    
    public async Task<HttpResponseMessage> UpdateNoteAsync(Guid id, CreateUpdateUserNoteRequest request)
        => await client.PutAsJsonAsync($"notes/{id}", request);

    public async Task<HttpResponseMessage> DeleteNoteAsync(Guid id)
        => await client.DeleteAsync($"notes/{id}");
}