using System.Net.Http.Json;
using PracticeAspNetCoreIdentity.Shared.Constants;
using PracticeAspNetCoreIdentity.Shared.Models;

namespace PracticeAspNetCoreIdentity.Client;

public class WebApiHttpClient(HttpClient client)
{
    // Authentication & User Management
    public async Task<HttpResponseMessage> CookieLoginAsync(string email, string password)
        => await client.PostAsJsonAsync("login?useCookies=true", new { email, password });

    public async Task<HttpResponseMessage> RegisterAsync(string email, string password)
        => await client.PostAsJsonAsync("register", new { email, password });

    public async Task<HttpResponseMessage> ResendConfirmationEmailAsync(string email)
        => await client.PostAsJsonAsync("resendConfirmationEmail", new { email });

    public async Task<HttpResponseMessage> ForgotPasswordAsync(string email)
        => await client.PostAsJsonAsync("forgotPassword", new { email });

    public async Task<HttpResponseMessage> ResetPasswordAsync(string email, string resetCode, string newPassword)
        => await client.PostAsJsonAsync("resetPassword", new { email, resetCode, newPassword });

    public async Task<HttpResponseMessage> GetUserInfoAsync()
        => await client.GetAsync("manage/info");

    public async Task<HttpResponseMessage> CookieLogoutAsync()
        => await client.PostAsync("cookie-logout", null);

    public async Task<HttpResponseMessage> GetUserRolesAsync()
        => await client.GetAsync("manage/roles");


    // Account Management
    public async Task<HttpResponseMessage> GetAllAccountsAsync(int page = 1, int pageSize = 10,
        string orderBy = AccountOrderBy.EmailAsc)
        => await client.GetAsync($"accounts?page={page}&pageSize={pageSize}&orderBy={orderBy}");

    public async Task<HttpResponseMessage> GetAccountCountAsync()
        => await client.GetAsync("accounts/count");

    public async Task<HttpResponseMessage> GetAccountByIdAsync(Guid id)
        => await client.GetAsync($"accounts/{id}");


    // User Notes Management
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