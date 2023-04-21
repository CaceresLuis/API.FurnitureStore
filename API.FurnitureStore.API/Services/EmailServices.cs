using Microsoft.Extensions.Options;
using API.FurnitureStore.API.Configoration;
using Microsoft.AspNetCore.Identity.UI.Services;
using MimeKit;
using MailKit.Net.Smtp;

namespace API.FurnitureStore.API.Services
{
    public class EmailServices : IEmailSender
    {
        private readonly SmtpSettings _settings;

        public EmailServices(IOptions<SmtpSettings> settings)
        {
            _settings = settings.Value;
        }

        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            try
            {
                var message = new MimeMessage();

                message.From.Add(new MailboxAddress(_settings.SenderName, _settings.SenderEmail));
                message.To.Add(new MailboxAddress("", email));
                message.Subject = subject;
                message.Body = new TextPart(htmlMessage);

                using (var client = new SmtpClient())
                {
                    await client.ConnectAsync(_settings.Server);
                    await client.AuthenticateAsync(_settings.UserName, _settings.Password);
                    await client.SendAsync(message);
                    await client.DisconnectAsync(true);
                }
            }
            catch (Exception)
            {

                throw;
            }
        }
    }
}
