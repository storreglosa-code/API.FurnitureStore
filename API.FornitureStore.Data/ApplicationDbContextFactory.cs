using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace API.FornitureStore.Data
{
    public class ApplicationDbContextFactory
        : IDesignTimeDbContextFactory<ApplicationDbContext>
    {
        public ApplicationDbContext CreateDbContext(string[] args)
        {
            var optionsBuilder = new DbContextOptionsBuilder<ApplicationDbContext>();

            // CONNECTION STRING LOCAL SOLO PARA MIGRACIONES
            optionsBuilder.UseNpgsql(
                "Host=localhost;Port=5432;Database=FurnitoreStoreDev;Username=postgres;Password=postgres"
            );

            return new ApplicationDbContext(optionsBuilder.Options);
        }
    }
}
