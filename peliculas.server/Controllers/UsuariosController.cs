using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using peliculas.server.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace peliculas.server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsuariosController : ControllerBase
    {
        private readonly UsuariosContext _context;
        private readonly IConfiguration _configuration;


        public UsuariosController(UsuariosContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;

        }
        [HttpPost]
        [Route("crear")]

        public async Task<IActionResult> CrearUsuario(Usuario usuario)
        {
            usuario.Password = BCrypt.Net.BCrypt.HashPassword(usuario.Password);
            await _context.Usuarios.AddAsync(usuario);
            await _context.SaveChangesAsync();

            return Ok(usuario);
        }

        [HttpGet]
        [Route("obtener")]

        public async Task<ActionResult<IEnumerable<Usuario>>> ObtenerUsuarios()
        {
            var usuarios = await _context.Usuarios.ToListAsync();

            return Ok(usuarios);
        }

        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var dbUsuario = await _context.Usuarios.FirstOrDefaultAsync(u => u.Email == loginModel.Email);
            if (dbUsuario == null || !BCrypt.Net.BCrypt.Verify(loginModel.Password, dbUsuario.Password))
            {
                return Unauthorized("Credenciales inválidas.");
            }

            var token = GenerarToken(dbUsuario);
            return Ok(new { token });
        }

        [HttpGet]
        [Route("perfil")]
        [Authorize]
        public IActionResult ObtenerPerfil()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            var userEmail = User.FindFirstValue(ClaimTypes.Email);

            return Ok(new { userId, userEmail });
        }
        private string GenerarToken(Usuario usuario)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, usuario.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(30),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

    }
}
