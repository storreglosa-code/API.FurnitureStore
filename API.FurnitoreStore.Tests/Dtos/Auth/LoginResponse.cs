using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace API.FurnitoreStore.Tests.Dtos.Auth;
public class LoginResponse
{
    public bool Result { get; set; }
    public string Token { get; set; }
    public string RefreshToken { get; set; }
    public int ClientId { get; set; }
    public string UserName { get; set; }
}
