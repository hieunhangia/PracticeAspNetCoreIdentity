namespace PracticeAspNetCoreIdentity.Shared.Models;

public class UserNoteDto
{
    public Guid Id { get; set; }
    public string? Name { get; set; }
    public string? Content { get; set; }
}