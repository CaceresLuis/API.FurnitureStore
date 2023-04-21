namespace API.FurnitureStore.Shared.Auth
{
    public class AuthResult
    {
        public string Token { get; set; }
        public bool Status { get; set; }
        public List<string> Errors { get; set; }
    }
}
