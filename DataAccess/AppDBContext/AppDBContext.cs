using InternIntelligence_USER_LOGIN_FUNCTIONALITY.Model;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace InternIntelligence_USER_LOGIN_FUNCTIONALITY.AppDBContext
{
    public class AppDBContext : IdentityDbContext<User, Role, Guid>
    {
        public AppDBContext(DbContextOptions<AppDBContext> options) : base(options)
        {
        }





        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            builder.Entity<User>().ToTable("Users");

            builder.Entity<Role>().ToTable("Roles");
        }
    }
}
