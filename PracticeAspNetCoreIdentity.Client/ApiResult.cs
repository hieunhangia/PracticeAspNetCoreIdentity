using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Serialization;

namespace PracticeAspNetCoreIdentity.Client;

public class ApiResult
{
    public bool Succeeded { get; private init; }
    public HttpStatusCode StatusCode { get; private init; }
    public IDictionary<string, string[]>? Errors { get; private init; }

    protected ApiResult()
    {
    }

    private static async Task<IDictionary<string, string[]>> ParseErrors(HttpResponseMessage response)
    {
        try
        {
            var problemDetails = await response.Content.ReadFromJsonAsync<ApiProblemDetails>();
            if (problemDetails == null)
                return new Dictionary<string, string[]> { ["Unknown Error"] = ["An unknown error occurred."] };
            if (problemDetails.Errors == null || problemDetails.Errors.Count == 0)
                return new Dictionary<string, string[]>
                    { [problemDetails.Title ?? "Error"] = [problemDetails.Detail ?? "An error occurred."] };
            return problemDetails.Errors;
        }
        catch (Exception e)
        {
            return new Dictionary<string, string[]> { ["Error"] = [$"An unexpected error occurred: {e.Message}"] };
        }
    }

    public static async Task<ApiResult> CreateAsync(HttpResponseMessage response) =>
        new()
        {
            Succeeded = response.IsSuccessStatusCode,
            StatusCode = response.StatusCode,
            Errors = response.IsSuccessStatusCode ? null : await ParseErrors(response)
        };

    public static async Task<ApiResult<T>> CreateAsync<T>(HttpResponseMessage response)
    {
        if (!response.IsSuccessStatusCode)
            return new ApiResult<T>
            {
                Succeeded = false,
                StatusCode = response.StatusCode,
                Errors = await ParseErrors(response)
            };
        try
        {
            return new ApiResult<T>
            {
                Succeeded = true,
                StatusCode = response.StatusCode,
                Data = await response.Content.ReadFromJsonAsync<T>()
            };
        }
        catch (Exception e)
        {
            return new ApiResult<T>
            {
                Succeeded = false,
                StatusCode = response.StatusCode,
                Errors = new Dictionary<string, string[]> { ["Error"] = [$"An unexpected error occurred: {e.Message}"] }
            };
        }
    }
}

public class ApiResult<T> : ApiResult
{
    public T? Data { get; init; }
}

public class ApiProblemDetails
{
    [JsonPropertyName("title")] public string? Title { get; init; }
    [JsonPropertyName("detail")] public string? Detail { get; init; }
    [JsonPropertyName("errors")] public IDictionary<string, string[]>? Errors { get; init; }
}