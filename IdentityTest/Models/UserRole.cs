﻿namespace IdentityTest.Models
{
    public class UserRole
    {
        public long UserId { get; set; }
        public int RoleId { get; set; }

        public User User { get; set; } = default!;
        public Role Role { get; set; } = default!;
    }
}
