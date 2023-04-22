namespace API.FurnitureStore.API.Configoration
{
    public class JwtConfig
    {
        public string Secret { get; set; }
        public TimeSpan Expirytime { get; set; }
    }
}
