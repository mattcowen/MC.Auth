using System;
using System.Collections.Generic;
using System.Globalization;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.OpenIdConnect;
using Orchard.ContentManagement;
using Orchard.Logging;
using Orchard.Owin;
using Orchard.Settings;
using System.Security.Claims;
using Owin;

namespace MC.Auth
{
    public class OwinMiddlewares : IOwinMiddlewareProvider
    {
        public ILogger Logger { get; set; }

        public OwinMiddlewares(ISiteService siteService)
        {
            Logger = NullLogger.Instance;

        }

        public IEnumerable<OwinMiddlewareRegistration> GetOwinMiddlewares()
        {
            var middlewares = new List<OwinMiddlewareRegistration>();

            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();
            
            middlewares.Add(new OwinMiddlewareRegistration { 
                Priority = "9", 
                Configure = app => {

                    // the following code is based on the Identity Server Hybrid client sample

                    app.UseCookieAuthentication(new CookieAuthenticationOptions
                    {
                        AuthenticationType = "Cookies"
                    });

                    app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
                    {
                        ClientId = "katanaclient",
                        Authority = "https://localhost:44333/core",
                        RedirectUri = "http://www.airflowenergy.local/admin/",
                        PostLogoutRedirectUri = "http://www.airflowenergy.local/",
                        ResponseType = "code id_token",
                        Scope = "openid profile read write offline_access",
                        UseTokenLifetime = false, // disable so sliding expiration works
                        SignInAsAuthenticationType = "Cookies",
                        

                        Notifications = new OpenIdConnectAuthenticationNotifications
                        {
                            SecurityTokenValidated = n =>
                            {
                                var x = "validated";

                                return Task.FromResult(0);
                            },

                            AuthorizationCodeReceived = async n =>
                            {
                                // use the code to get the access and refresh token
                                var tokenClient = new TokenClient(
                                    "https://localhost:44333/core/connect/token",
                                    "katanaclient",
                                    "secret");

                                var response = await tokenClient.RequestAuthorizationCodeAsync(n.Code, n.RedirectUri);
                                var id = new ClaimsIdentity(n.AuthenticationTicket.Identity.AuthenticationType);

                                var preferredClaims = new[] { "given_name", "family_name", "name", "nonce", "sub" };
                                foreach (var preferredClaim in preferredClaims)
                                {
                                    var claim = n.AuthenticationTicket.Identity.FindFirst(preferredClaim);
                                    if (claim != null)
                                    {
                                        id.AddClaim(claim);
                                    }
                                }

                                id.AddClaim(new Claim("access_token", response.AccessToken));
                                id.AddClaim(new Claim("expires_at", DateTime.Now.AddSeconds(response.ExpiresIn).ToLocalTime().ToString()));
                                id.AddClaim(new Claim("refresh_token", response.RefreshToken));
                                id.AddClaim(new Claim("id_token", n.ProtocolMessage.IdToken)); // keep the token for logout
                                id.AddClaims(id.FindAll("roles"));

                                // create a new claims identity and specify the claim type names for name and role 
                                var nid = new ClaimsIdentity(n.AuthenticationTicket.Identity.AuthenticationType, "name", "role");
                                nid.AddClaims(id.Claims);


                                n.AuthenticationTicket = new AuthenticationTicket(
                                    nid,
                                    n.AuthenticationTicket.Properties);

                                
                            },

                            RedirectToIdentityProvider = n =>
                            {
                                // if signing out, add the id_token_hint
                                if (n.ProtocolMessage.RequestType == OpenIdConnectRequestType.LogoutRequest)
                                {
                                    var idTokenHint = n.OwinContext.Authentication.User.FindFirst("id_token");

                                    if (idTokenHint != null)
                                    {
                                        n.ProtocolMessage.IdTokenHint = idTokenHint.Value;
                                    }

                                }

                                return Task.FromResult(0);
                            }
                        }
                    });

                }
                });

            

            return middlewares;
        }
    }




}