using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using PracticeAspNetCoreIdentity.Server.Models;

namespace PracticeAspNetCoreIdentity.Server.Controllers.ActionFilterAttributes;

public class RequireConfirmedEmailAttribute : ActionFilterAttribute
{
    public override async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        var user = context.HttpContext.User;
        if (user.Identity is not { IsAuthenticated: true })
        {
            await next();
            return;
        }

        var userManager = context.HttpContext.RequestServices.GetRequiredService<UserManager<CustomUser>>();
        var currentUser = await userManager.GetUserAsync(user);

        if (currentUser != null && !await userManager.IsEmailConfirmedAsync(currentUser))
        {
            context.Result = new ObjectResult(new ProblemDetails
            {
                Title = "Email not confirmed",
                Detail = "You must confirm your email to access this resource.",
                Status = StatusCodes.Status403Forbidden
            })
            {
                StatusCode = StatusCodes.Status403Forbidden
            };
            return;
        }

        await next();
    }
}