using Microsoft.EntityFrameworkCore;

namespace peliculas.server.Models
{
    public class UsuariosContext : DbContext
    {
        public UsuariosContext(DbContextOptions<UsuariosContext> options) : base(options)
        {
           
        }
        // Agregamos la clase a la base de datos
        public DbSet<Usuario> Usuarios { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);
            modelBuilder.Entity<Usuario>().HasIndex(user => user.Email).IsUnique();
        }
    }
}
