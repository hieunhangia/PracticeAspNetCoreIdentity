using System.ComponentModel.DataAnnotations;

namespace PracticeAspNetCoreIdentity.Shared.Models.Identity;

public class GoogleLoginRequest
{
    [Required] public required string IdToken { get; init; }
}