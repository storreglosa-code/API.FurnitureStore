namespace API.FurnitoreStore.Share.Auth
{
    public class LoginResponse
    {
        public string Token { get; set; }
        public bool Result { get; set; }
        public int ClientId { get; set; }
        public string UserName { get; set; }
        public List<string> Errors { get; set; }
        public string RefreshToken { get; set; }
    }
}
