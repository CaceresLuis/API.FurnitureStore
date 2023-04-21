namespace API.FurnitureStore.API.Configoration
{
    public class SmtpSettings
    {
        public string Server { get; set; }
        public int Port { get; set; }
        public string SenderEmail { get; set; }
        public string UserName { get; set; }
        public string SenderName => UserName ?? string.Empty;
        public string Password { get; set; }
    }
}
