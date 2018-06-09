using Microsoft.Owin.Security.OAuth;
using Microsoft.Owin;
using System;

namespace aspnet_owin_oath
{
    internal class MyOAuthOptions : OAuthAuthorizationServerOptions
    {
        public MyOAuthOptions()
        {
            TokenEndpointPath = new PathString("/token");
            AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(60);
            AccessTokenFormat = new MyJwtFormat(60);
            Provider = new MyOauthProvider();
#if DEBUG
            AllowInsecureHttp = true;
#endif
        }
    }
}