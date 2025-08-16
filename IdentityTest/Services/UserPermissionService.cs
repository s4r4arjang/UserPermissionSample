using IdentityTest.Context;
using Microsoft.EntityFrameworkCore;

namespace IdentityTest.Services
{
    public class UserPermissionService : IUserPermissionService
    {
        private readonly AppDbContext _db;
        public UserPermissionService(AppDbContext db) => _db = db;

        public async Task<List<string>> GetPermissionsAsync(long userId)
        {
            var perms = await _db.UserRoles
                .Where(ur => ur.UserId == userId)
                .SelectMany(ur => ur.Role.RolePermissions)
                .Select(rp => rp.Permission.Title)
                .Distinct()
                .ToListAsync();

            return perms;
        }
    }
}
