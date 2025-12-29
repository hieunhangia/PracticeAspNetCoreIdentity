using System.ComponentModel.DataAnnotations;

namespace PracticeAspNetCoreIdentity.Shared.Models;

public class BanUserRequest
{
    [Required]
    [Range(1, long.MaxValue, ErrorMessage = "Ban time must be a positive integer.")]
    public long BanTimeInSeconds { get; set; }
}