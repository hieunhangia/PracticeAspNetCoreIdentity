namespace PracticeAspNetCoreIdentity.Shared.Models.UserNote;

public class UserNoteDto
{
    public required Guid Id { get; init; }
    public required string Name { get; init; }
    public required string Content { get; init; }
}