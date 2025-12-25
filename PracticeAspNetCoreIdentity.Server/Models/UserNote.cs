namespace PracticeAspNetCoreIdentity.Server.Models;

public class UserNote
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    
    public Guid UserId { get; set; }
    public CustomUser? User { get; set; }
}