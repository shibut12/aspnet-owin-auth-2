using Microsoft.Owin.Security;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace aspnet_owin_oath
{
    internal class MyJwtFormat : ISecureDataFormat<AuthenticationTicket>
    {
        private readonly int _timeout;

        public MyJwtFormat(int timeout)
        {
            _timeout = timeout;
        }

        public string SignatureAlgorithm
        {
            get { return "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"; }
        }

        public string DigestAlgorithm
        {
            get { return "http://www.w3.org/2001/04/xmlenc#sha256"; }
        }

        public string Protect(AuthenticationTicket data)
        {
            if (data == null) throw new ArgumentNullException("data");

            var issuer = "localhost";
            var audience = "all";
            var key = Convert.FromBase64String("NDI0NzQzZGItZDRlNS00YWNhLTgxYTctYTQyYmY5M2RmM2Iw");
            var now = DateTime.UtcNow;
            var expires = now.AddMinutes(_timeout);

            var securityKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(key);
            var signingCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(securityKey, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256Signature);

            var token = new JwtSecurityToken(issuer, audience, data.Identity.Claims, now, expires, signingCredentials);

            var handler = new JwtSecurityTokenHandler();

            return handler.WriteToken(token);
        }

        public AuthenticationTicket Unprotect(string protectedText)
        {
            throw new System.NotImplementedException();
        }
    }
}