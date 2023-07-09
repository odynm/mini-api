using Microsoft.EntityFrameworkCore;
using MinimalApi.Models;

namespace MinimalApi.Data
{
    public class ContextDb : DbContext
    {
        public ContextDb(DbContextOptions<ContextDb> options) : base(options) { }

        public DbSet<Player> Players { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Player>()
                .HasKey(x => x.Id);

            modelBuilder.Entity<Player>()
                .Property(x => x.Name)
                .IsRequired()
                .HasColumnType("varchar(200)");

            modelBuilder.Entity<Player>()
                .ToTable("Players");

            base.OnModelCreating(modelBuilder);
        }
    }
}
