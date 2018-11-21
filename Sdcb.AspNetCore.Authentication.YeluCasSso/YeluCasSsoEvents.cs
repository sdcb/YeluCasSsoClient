using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.OAuth;

namespace Sdcb.AspNetCore.Authentication.YeluCasSso
{
    public sealed class YeluCasSsoEvents : OAuthEvents
    {
        /// <summary>
        /// Gets or sets the function that is invoked when the CreatingClaims method is invoked.
        /// </summary>
        public Func<ClaimsIdentity, Task> OnCreatingClaims { get; set; } = c =>
        {
            CreateDefaultClaims(c);
            return Task.CompletedTask;
        };

        /// <summary>
        /// Invoked before calling CreatingTicket.
        /// </summary>
        /// <param name="identity">Contains the user System.Security.Claims.ClaimsIdentity.</param>
        /// <returns>A System.Threading.Tasks.Task representing the completed operation.</returns>
        public Task CreatingClaims(ClaimsIdentity identity)
        {
            return OnCreatingClaims(identity);
        }

        public static void CreateDefaultClaims(ClaimsIdentity claimsIdentity)
        {
            claimsIdentity.AddClaims(claimsIdentity.Claims
                .Where(x => CasClaimsMap.ContainsKey(x.Type))
                .Select(x => new Claim(CasClaimsMap[x.Type], x.Value)));
        }

        public static Dictionary<string, string> CasClaimsMap = new Dictionary<string, string>
        {
            ["cas:id"] = ClaimTypes.NameIdentifier,
            ["cas:name"] = ClaimTypes.Name,
            ["cas:email"] = ClaimTypes.Email, 
            ["cas:gender"] = ClaimTypes.Gender, 
            ["cas:phone"] = ClaimTypes.MobilePhone, 
            ["cas:jobNumber"] = ClaimTypes.SerialNumber, 
        };
    }
}
