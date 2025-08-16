namespace IdentityTest.Models
{
    public class Role
    {
        public int Id { get; set; }
        public string Title { get; set; } = default!; // e.g., Admin, Librarian

        public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
        public ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
    }
}
