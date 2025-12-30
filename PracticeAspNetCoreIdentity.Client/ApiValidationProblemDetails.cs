using System.Text.Json.Serialization;

namespace PracticeAspNetCoreIdentity.Client;

public class ApiValidationProblemDetails
{
    [JsonPropertyName("type")]
    public string? Type { get; init; }
    
    [JsonPropertyName("title")]
    public string? Title { get; init; }
    
    [JsonPropertyName("status")]
    public int? Status { get; init; }
    
    [JsonPropertyName("detail")]
    public string? Detail { get; init; }
    
    [JsonPropertyName("instance")]
    public string? Instance { get; init; }

    [JsonPropertyName("errors")]
    public IDictionary<string, string[]>? Errors { get; init; }
    
    [JsonExtensionData]
    public IDictionary<string, object?> Extensions { get; init; } = new Dictionary<string, object?>(StringComparer.Ordinal);

}