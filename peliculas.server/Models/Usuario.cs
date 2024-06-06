using System.ComponentModel.DataAnnotations;

namespace peliculas.server.Models
{
    public class Usuario
    {
        public int Id { get; set; }

        public string Nombre { get; set; } = null!;

        public string Apellidos { get; set; } = null!;

        public string Email {  get; set; } = null!;
        public string Password { get; set; } = null!;


    }
}
