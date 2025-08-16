namespace IdentityTest.Models
{
    public class RolePermission
    {
        public int RoleId { get; set; }
        public long PermissionId { get; set; }

        public Role Role { get; set; } = default!;
        public Permission Permission { get; set; } = default!;
    }
}
