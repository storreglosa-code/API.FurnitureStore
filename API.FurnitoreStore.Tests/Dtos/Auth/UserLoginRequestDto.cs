using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace API.FurnitoreStore.Tests.Dtos.Auth;
public class UserLoginRequestDto
{
    public string Email { get; set; }
    public string Password { get; set; }
}
