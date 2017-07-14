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
    using System.Threading.Tasks;
    using System.Linq;
    using Microsoft.Identity.Client;
    using Utils;
    using System;
    using System.Security.Claims;
    using System.Web;

    public static class AuthHelper
    {
        public const string ObjectIdentifierClaim = "http://schemas.microsoft.com/identity/claims/objectidentifier";
        private const string AuthContextCacheKey = "authContext";

        internal static Task GetUserAccessTokenSilentAsync(string[] v, HttpContextBase httpContext, object redirectUri)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Silently retrieve a new access token for the specified resource. If the request fails, null is returned.
        /// </summary>
        /// <param name="resource"></param>
        /// <returns></returns>
        public static async Task<string> GetUserAccessTokenSilentAsync(string[] scopes, string redirectUri, MSALPersistentTokenCache cachedContext = null)
        {
            // try to get token silently
            string signedInUserID = ClaimsPrincipal.Current.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            TokenCache userTokenCache = cachedContext?.GetMsalCacheInstance() ?? new MSALPersistentTokenCache(signedInUserID).GetMsalCacheInstance();
            ConfidentialClientApplication cca = new ConfidentialClientApplication(SettingsHelper.ClientId, redirectUri, new ClientCredential(SettingsHelper.AppKey), userTokenCache, null);
            if (cca.Users.Count() > 0)
            {
                try
                {
                    AuthenticationResult result = await cca.AcquireTokenSilentAsync(scopes, cca.Users.First());
                    return result.AccessToken;
                }
                catch (MsalUiRequiredException)
                {
                }
            }
            
            return null;
        }

        /// <summary>
        /// Return the signed in user's identifier
        /// </summary>
        /// <returns></returns>
        public static string GetUserId()
        {
            string signedInUserID = ClaimsPrincipal.Current.FindFirst(ObjectIdentifierClaim)?.Value;
            return signedInUserID;
        }
    }
}