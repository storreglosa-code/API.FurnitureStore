namespace API.FurnitoreStore.API.Configuration
{
    public class JWTConfig
    {
        public string Secret { get; set; }

        public TimeSpan ExpiryTime { get; set; }
    }
}
