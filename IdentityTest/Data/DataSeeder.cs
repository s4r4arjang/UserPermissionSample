using IdentityTest.Context;
using IdentityTest.Models;
using Microsoft.EntityFrameworkCore;

namespace IdentityTest.Data;

public static class DataSeeder
{
    public static async Task SeedAsync(AppDbContext db)
    {
        // Roles
        if (!db.Roles.AsNoTracking().Any())
        {
            var admin = new Role { Title = "Admin" };
            var librarian = new Role { Title = "Librarian" };
            db.Roles.AddRange(admin, librarian);
            await db.SaveChangesAsync();
        }

        // Permissions
        if (!db.Permissions.AsNoTracking().Any())
        {
            var pRead = new Permission { Title = "books.read", DisplayName = "Read books" };
            var pWrite = new Permission { Title = "books.write", DisplayName = "Write books" };
            db.Permissions.AddRange(pRead, pWrite);
            await db.SaveChangesAsync();
        }

        // RolePermissions
        if (!db.RolePermissions.AsNoTracking().Any())
        {
            var adminRole = await db.Roles.FirstAsync(r => r.Title == "Admin");
            var librarianRole = await db.Roles.FirstAsync(r => r.Title == "Librarian");
            var pRead = await db.Permissions.FirstAsync(p => p.Title == "books.read");
            var pWrite = await db.Permissions.FirstAsync(p => p.Title == "books.write");

            db.RolePermissions.AddRange(
                new RolePermission { RoleId = adminRole.Id, PermissionId = pRead.Id },
                new RolePermission { RoleId = adminRole.Id, PermissionId = pWrite.Id },
                new RolePermission { RoleId = librarianRole.Id, PermissionId = pRead.Id }
            );
            await db.SaveChangesAsync();
        }

        // Users
        if (!db.Users.AsNoTracking().Any())
        {
            var adminUser = new User
            {
                Username = "admin",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("admin123!")
            };
            var normalUser = new User
            {
                Username = "sara",
                PasswordHash = BCrypt.Net.BCrypt.HashPassword("sara123!")
            };
            db.Users.AddRange(adminUser, normalUser);
            await db.SaveChangesAsync();

            var adminRole = await db.Roles.FirstAsync(r => r.Title == "Admin");
            var librarianRole = await db.Roles.FirstAsync(r => r.Title == "Librarian");

            db.UserRoles.AddRange(
                new UserRole { UserId = adminUser.Id, RoleId = adminRole.Id },
                new UserRole { UserId = normalUser.Id, RoleId = librarianRole.Id }
            );
            await db.SaveChangesAsync();
        }
    }
}