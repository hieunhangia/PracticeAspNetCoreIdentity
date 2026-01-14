using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using PracticeAspNetCoreIdentity.Server.Models;

namespace PracticeAspNetCoreIdentity.Server.Controllers.ActionFilterAttributes;

public class RequireConfirmedEmailAttribute : ActionFilterAttribute
{
    public override async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        if (context.HttpContext.User.Identity is not { IsAuthenticated: true })
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        var userManager = context.HttpContext.RequestServices.GetRequiredService<UserManager<AppUser>>();
        var currentUser = await userManager.GetUserAsync(context.HttpContext.User);

        if (currentUser == null)
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        if (!currentUser.EmailConfirmed)
        {
            context.Result = new ObjectResult(new ProblemDetails
            {
                Title = "Email not confirmed",
                Detail = "You must confirm your email to do this action.",
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