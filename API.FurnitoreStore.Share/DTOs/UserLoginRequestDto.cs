using System.ComponentModel.DataAnnotations;

namespace API.FurnitoreStore.Share.DTOs
{
    public class UserLoginRequestDto
    {
        [Required]
        public string Email { get; set; }

        [Required]
        public string Password { get; set; }
    }
}
