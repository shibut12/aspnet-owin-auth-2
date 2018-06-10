using Owin;
using System.Web.Http;

namespace aspnet_owin_oath
{
    public class Startup
    {
        public void Configuration(IAppBuilder appBuilder)
        {
            HttpConfiguration httpConfiguration = new HttpConfiguration();

            appBuilder.UseOAuthAuthorizationServer(new MyOAuthOptions());
            appBuilder.UseJwtBearerAuthentication(new MyJwtOptions());

            httpConfiguration.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );

            appBuilder.UseWebApi(httpConfiguration);
        }
    }
}