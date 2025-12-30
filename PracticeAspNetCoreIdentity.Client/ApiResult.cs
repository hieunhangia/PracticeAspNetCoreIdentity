namespace PracticeAspNetCoreIdentity.Client;

public class ApiResult
{
    public bool Succeeded { get; protected init; }
    public IEnumerable<string> ErrorList { get; protected init; } = [];

    protected ApiResult()
    {
    }

    public static ApiResult Success() => new() { Succeeded = true };
    
    public static ApiResult Failure(params string[] errors)
        => new() { Succeeded = false, ErrorList = errors };
    
    public static ApiResult Failure(IEnumerable<string> errors)
        => new() { Succeeded = false, ErrorList = errors };
}

public class ApiResult<T> : ApiResult
{
    public T? Data { get; init; }

    public static ApiResult<T> Success(T data) => new() { Succeeded = true, Data = data };
    
    public new static ApiResult<T> Failure(params string[] errors)
        => new() { Succeeded = false, ErrorList = errors, Data = default };

    public new static ApiResult<T> Failure(IEnumerable<string> errors)
        => new() { Succeeded = false, ErrorList = errors, Data = default };
}