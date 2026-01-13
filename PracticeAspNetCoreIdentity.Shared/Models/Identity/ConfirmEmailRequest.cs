using System.ComponentModel.DataAnnotations;

namespace PracticeAspNetCoreIdentity.Shared.Models.Identity;

public class ConfirmEmailRequest
{
    [Required] public required string UserId { get; init; }

    [Required] public required string Code { get; init; }
}