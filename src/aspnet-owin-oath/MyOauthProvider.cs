using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace aspnet_owin_oath
{
    internal class MyOauthProvider : OAuthAuthorizationServerProvider
    {
        public override Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {
            string userName = context.UserName;
            string passWord = context.Password;

            if(string.IsNullOrEmpty(userName) || string.IsNullOrEmpty(passWord))
            {
                context.SetError("Invalid credentials");
                context.Rejected();
            }

            if(userName == passWord)
            {
                List<Claim> claims = new List<Claim>();
                claims.Add(new Claim("name", userName));
                ClaimsIdentity oAuthIdentity = new ClaimsIdentity(claims, "JWT");

                JObject wrappedCustomerProfile = new JObject(
                            new JProperty("stat", "ok"),
                            new JProperty("result", "result")
                            );
                var FormattedCustomerProfile = JsonConvert.SerializeObject(wrappedCustomerProfile, Formatting.None);
                var AdditionalProperties = new AuthenticationProperties(new Dictionary<string, string>
                    {
                        {
                            "data", FormattedCustomerProfile
                        }
                    });

                var ticket = new AuthenticationTicket(oAuthIdentity, AdditionalProperties);
                context.Validated(ticket);
            }

            return Task.FromResult(0);
        }

        public override Task TokenEndpointResponse(OAuthTokenEndpointResponseContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
            {
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }

            return Task.FromResult(0);
        }

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            context.Validated();
            return Task.FromResult(0);
        }
    }
}