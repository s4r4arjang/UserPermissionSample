using Microsoft.AspNetCore.Authorization;

namespace IdentityTest.Authorization
{
    public class PermissionHandler : AuthorizationHandler<PermissionRequirement>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirement requirement)
        {
            var has = context.User.Claims.Any(c => c.Type == "permission" &&
                                                   string.Equals(c.Value, requirement.PermissionName, StringComparison.OrdinalIgnoreCase));
            if (has) context.Succeed(requirement);
            else context.Fail();
            return Task.CompletedTask;
        }
    }
}
