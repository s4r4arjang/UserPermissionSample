namespace IdentityTest.Services
{
    public interface IUserPermissionService
    {
        Task<List<string>> GetPermissionsAsync(long userId);
    }
}
