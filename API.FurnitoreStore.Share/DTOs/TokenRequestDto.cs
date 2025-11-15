using System.ComponentModel.DataAnnotations;

namespace API.FurnitoreStore.Share.DTOs
{
    public class TokenRequestDto
    {
       [Required]
       public string Token {  get; set; }

       [Required]
       public string RefreshToken { get; set; }
    }
}
