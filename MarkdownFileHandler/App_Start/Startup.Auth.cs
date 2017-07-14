/*
 * Markdown File Handler - Sample Code
 * Copyright (c) Microsoft Corporation
 * All rights reserved. 
 * 
 * MIT License
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy of 
 * this software and associated documentation files (the ""Software""), to deal in 
 * the Software without restriction, including without limitation the rights to use, 
 * copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the
 * Software, and to permit persons to whom the Software is furnished to do so, 
 * subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all 
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, 
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION 
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE 
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

namespace MarkdownFileHandler
{
    using System;
    using System.Threading.Tasks;
    using System.Web;
    using Microsoft.Owin.Security;
    using Microsoft.Owin.Security.Cookies;
    using Microsoft.Owin.Security.OpenIdConnect;
    using Owin;
    using Microsoft.Identity.Client;
    using MarkdownFileHandler.Utils;
    using Models;
    using Controllers;
    using System.Globalization;
    using System.IdentityModel.Tokens;
    using System.IdentityModel.Claims;
    
    public partial class Startup
    {
       
        public void ConfigureAuth(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

            app.UseCookieAuthentication(new CookieAuthenticationOptions { });

            var clientId = SettingsHelper.ClientId;
            var appKey = SettingsHelper.AppKey;
            var aadInstance = SettingsHelper.Authority;
            string redirectUri = SettingsHelper.RedirectUri;
            var scopes = new string[] { "User.Read", "Files.ReadWrite.All" };

            //app.UseOAuth2CodeRedeemer(
            //    new OAuth2CodeRedeemerOptions
            //    {
            //        ClientId = clientId,
            //        ClientSecret = appKey,
            //        RedirectUri = redirectUri
            //    });

            app.UseOpenIdConnectAuthentication(
                new OpenIdConnectAuthenticationOptions
                {
                    // The `Authority` represents the v2.0 endpoint - https://login.microsoftonline.com/common/v2.0
                    // The `Scope` describes the initial permissions that your app will need.  See https://azure.microsoft.com/documentation/articles/active-directory-v2-scopes/                    
                    ClientId = SettingsHelper.ClientId,
                    Authority = String.Format(CultureInfo.InvariantCulture, SettingsHelper.Authority, "common", "/v2.0"),
                    RedirectUri = redirectUri,
                    Scope = "openid profile " + string.Join(" ", scopes),
                    PostLogoutRedirectUri = "/",
                    TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = false,
                        // In a real application you would use IssuerValidator for additional checks, like making sure the user's organization has signed up for your app.
                        //     IssuerValidator = (issuer, token, tvp) =>
                        //     {
                        //        //if(MyCustomTenantValidation(issuer)) 
                        //        return issuer;
                        //        //else
                        //        //    throw new SecurityTokenInvalidIssuerException("Invalid issuer");
                        //    },
                    },
                    Notifications = new OpenIdConnectAuthenticationNotifications
                    {
                        // If there is a code in the OpenID Connect response, redeem it for an access token and refresh token, and store those away.
                        AuthorizationCodeReceived = async (context) =>
                        {
                            var code = context.Code;
                            string signedInUserID = context.AuthenticationTicket.Identity.FindFirst(ClaimTypes.NameIdentifier).Value;
                            TokenCache userTokenCache = new MSALPersistentTokenCache(signedInUserID).GetMsalCacheInstance();
                            ConfidentialClientApplication cca =
                                new ConfidentialClientApplication(clientId, redirectUri, new ClientCredential(appKey), userTokenCache, null);
                            try
                            {
                                AuthenticationResult result = await cca.AcquireTokenByAuthorizationCodeAsync(code, scopes);
                            }
                            catch (Exception eee)
                            {

                            }
                        },
                        AuthenticationFailed = (notification) =>
                        {
                            notification.HandleResponse();
                            notification.Response.Redirect("/Error?message=" + notification.Exception.Message);
                            return Task.FromResult(0);
                        },
                        RedirectToIdentityProvider = (context) =>
                        {
                            // This ensures that the address used for sign in and sign out is picked up dynamically from the request
                            // this allows you to deploy your app (to Azure Web Sites, for example)without having to change settings
                            // Remember that the base URL of the address used here must be provisioned in Azure AD beforehand.
                            context.ProtocolMessage.RedirectUri = SettingsHelper.RedirectUri;
                            context.ProtocolMessage.PostLogoutRedirectUri = SettingsHelper.RedirectUri;

                            FileHandlerActivationParameters fileHandlerActivation;
                            if (FileHandlerController.IsFileHandlerActivationRequest(new HttpRequestWrapper(HttpContext.Current.Request), out fileHandlerActivation))
                            {
                                // Add LoginHint and DomainHint if the request includes a form handler post
                                context.ProtocolMessage.LoginHint = fileHandlerActivation.UserId;
                                context.ProtocolMessage.DomainHint = fileHandlerActivation.DomainHint;

                                // Save the form in the cookie to prevent it from getting lost in the login redirect
                                if (HttpContext.Current.Request.Form.Count > 0)
                                {
                                    CookieStorage.Save(HttpContext.Current.Request.Form, HttpContext.Current.Response);
                                }
                            }

                            // Allow us to change the prompt in consent mode if the challenge properties specify a prompt type
                            var challengeProperties = context.OwinContext?.Authentication?.AuthenticationResponseChallenge?.Properties;
                            if (null != challengeProperties && challengeProperties.Dictionary.ContainsKey("prompt"))
                            {
                                context.ProtocolMessage.Prompt = challengeProperties.Dictionary["prompt"];
                            }

                            return Task.FromResult(0);
                        }
                    }
                }
            );
        }
    }
}
