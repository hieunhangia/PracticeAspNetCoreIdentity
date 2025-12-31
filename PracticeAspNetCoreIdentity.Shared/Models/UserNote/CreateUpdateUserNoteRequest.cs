using System.ComponentModel.DataAnnotations;

namespace PracticeAspNetCoreIdentity.Shared.Models.UserNote;

public class CreateUpdateUserNoteRequest
{
    [Required]
    [MaxLength(100)]
    public required string Name { get; set; }
    
    [Required]
    public required string Content { get; set; }
}