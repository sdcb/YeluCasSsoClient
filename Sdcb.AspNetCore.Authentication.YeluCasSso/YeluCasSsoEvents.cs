using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;

namespace Sdcb.AspNetCore.Authentication.YeluCasSso
{
    public sealed class YeluCasSsoEvents : OAuthEvents
    {
        /// <summary>
        /// Gets or sets the function that is invoked when the CreatingClaims method is invoked.
        /// </summary>
        public Func<HttpContext, ClaimsIdentity, Task> OnCreatingClaims { get; set; } = (h, c) =>
        {
            CreateDefaultClaims(c);
            return Task.CompletedTask;
        };

        /// <summary>
        /// Invoked before calling CreatingTicket.
        /// </summary>
        /// <param name="identity">Contains the user System.Security.Claims.ClaimsIdentity.</param>
        /// <returns>A System.Threading.Tasks.Task representing the completed operation.</returns>
        public Task CreatingClaims(HttpContext httpContext, ClaimsIdentity identity)
        {
            return OnCreatingClaims(httpContext, identity);
        }

        public static void CreateDefaultClaims(ClaimsIdentity claimsIdentity)
        {
            claimsIdentity.AddClaims(claimsIdentity.Claims
                .Where(x => CasClaimsMap.ContainsKey(x.Type))
                .Select(x => new Claim(CasClaimsMap[x.Type], x.Value)));
        }

        public static Dictionary<string, string> CasClaimsMap = new Dictionary<string, string>
        {
            [CasConstants.Id] = ClaimTypes.NameIdentifier,
            [CasConstants.Name] = ClaimTypes.Name,
            [CasConstants.Email] = ClaimTypes.Email, 
            [CasConstants.Gender] = ClaimTypes.Gender, 
            [CasConstants.Phone] = ClaimTypes.MobilePhone, 
            [CasConstants.JobNumber] = ClaimTypes.SerialNumber, 
        };
    }
}
