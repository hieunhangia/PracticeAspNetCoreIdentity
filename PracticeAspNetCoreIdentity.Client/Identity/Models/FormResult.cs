namespace PracticeAspNetCoreIdentity.Client.Identity.Models;

public class FormResult
{
    public bool Succeeded { get; set; }
    public IEnumerable<string> ErrorList { get; set; } = [];
}