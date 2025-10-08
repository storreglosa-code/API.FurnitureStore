namespace API.FurnitoreStore.API.Configuration
{
    public class JWTConfig
    {
        public string Secret { get; set; }

        public string Issuer { get; set; }

        public string Audience { get; set; }

        public TimeSpan ExpiryTime { get; set; }
    }
}
