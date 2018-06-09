using Microsoft.Owin.Security.Jwt;
using System;

namespace aspnet_owin_oath
{
    internal class MyJwtOptions : JwtBearerAuthenticationOptions
    {
        public MyJwtOptions()
        {
            var issuer = "localhost";
            var audience = "all";
            var key = Convert.FromBase64String("NDI0NzQzZGItZDRlNS00YWNhLTgxYTctYTQyYmY5M2RmM2Iw"); ;

            AllowedAudiences = new[] { audience };
            IssuerSecurityKeyProviders = new IIssuerSecurityKeyProvider[]
            {
                new SymmetricKeyIssuerSecurityKeyProvider(issuer, key)
            };
        }
    }
}