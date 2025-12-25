using System.ComponentModel.DataAnnotations;

namespace PracticeAspNetCoreIdentity.Shared.Models;

public class CreateUpdateUserNoteRequest
{
    [Required]
    [MaxLength(100)]
    public string? Name { get; set; }
    
    [Required]
    public string? Content { get; set; }
}