using System.ComponentModel.DataAnnotations;

namespace PracticeAspNetCoreIdentity.Shared.Models;

public class BanUserRequest
{
    [Required]
    [Range(1, 315360000, ErrorMessage = "Ban time must be between 1 second and 315,360,000 seconds (10 year).")]
    public long BanTimeInSeconds { get; set; }
}