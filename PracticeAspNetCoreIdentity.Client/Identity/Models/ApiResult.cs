namespace PracticeAspNetCoreIdentity.Client.Identity.Models;

public class ApiResult
{
    public object? Data { get; set; }
    public bool Succeeded { get; set; }
    public IEnumerable<string> ErrorList { get; set; } = [];
}