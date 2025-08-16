namespace IdentityTest.Models
{
    public class Permission
    {
        public long Id { get; set; }
        public string Title { get; set; } = default!; // e.g., books.read
        public string? DisplayName { get; set; }

        public ICollection<RolePermission> RolePermissions { get; set; } = new List<RolePermission>();
    }
}
