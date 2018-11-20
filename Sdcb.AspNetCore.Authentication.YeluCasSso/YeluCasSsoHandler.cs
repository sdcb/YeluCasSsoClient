using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using System.Web;
using System.Xml;
using System.Xml.Linq;
using System.Xml.XPath;

namespace Sdcb.AspNetCore.Authentication.YeluCasSso
{
    public partial class YeluCasSsoHandler : OAuthHandler<YeluCasSsoOptions>
    {
        const string NamespaceName = "http://www.yale.edu/tp/cas";

        public YeluCasSsoHandler(IOptionsMonitor<YeluCasSsoOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        {
        }

        protected new YeluCasSsoEvents Events
        {
            get { return (YeluCasSsoEvents)base.Events; }
            set { base.Events = value; }
        }

        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            IQueryCollection query = Request.Query;

            var state = query["state"];
            var properties = Options.StateDataFormat.Unprotect(state);

            if (properties == null)
            {
                return HandleRequestResult.Fail("The oauth state was missing or invalid.");
            }

            string ticket = query["ticket"].FirstOrDefault();
            string returnUrl = query["returnUrl"].FirstOrDefault();
            if (ticket == null)
            {
                return HandleRequestResult.Fail("Ticket should never be null.");
            }

            string serviceUri = CurrentUri;
            string userInformationUrl = QueryHelpers.AddQueryString(Options.UserInformationEndpoint, new Dictionary<string, string>
            {
                ["ticket"] = ticket, 
                ["service"] = GetService(CurrentUri)
            });
            HttpResponseMessage response = await Backchannel.GetAsync(userInformationUrl);
            var xdoc = XDocument.Load(await response.Content.ReadAsStreamAsync());

            string xmlErrorMessage = GetXmlErrorMessage(xdoc);
            if (xmlErrorMessage != null)
            {
                return HandleRequestResult.Fail(xmlErrorMessage);
            }

            IEnumerable<Claim> claims = GetXmlClaims(xdoc);
            var identity = new ClaimsIdentity(claims, ClaimsIssuer);

            var token = OAuthTokenResponse.Failed(new Exception("Token not available."));
            AuthenticationTicket authenticationTicket = await CreateTicketAsync(identity, properties, token);
            if (authenticationTicket != null)
            {
                return HandleRequestResult.Success(authenticationTicket);
            }
            else
            {
                return HandleRequestResult.Fail("Failed to retrieve user information from remote user.", properties);
            }
        }

        protected override async Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
        {
            // available options: 
            // gender(number), phone(string), name(string), id(number), email(string), jobNumber(string)
            identity.AddClaim(new Claim(ClaimTypes.Name, identity.FindFirst("name").Value));
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, identity.FindFirst("id").Value));
            identity.AddClaim(new Claim(ClaimTypes.Email, identity.FindFirst("email").Value));
            identity.AddClaim(new Claim(ClaimTypes.Gender, identity.FindFirst("gender").Value));
            identity.AddClaim(new Claim(ClaimTypes.MobilePhone, identity.FindFirst("phone").Value));
            identity.AddClaim(new Claim(ClaimTypes.SerialNumber, identity.FindFirst("jobNumber").Value));

            var context = new OAuthCreatingTicketContext(new ClaimsPrincipal(identity), properties, Context, Scheme, Options, Backchannel, tokens);
            await Events.CreatingTicket(context);
            return new AuthenticationTicket(new ClaimsPrincipal(identity), properties, Scheme.Name);
        }

        private string GetService(string url)
        {
            var uri = new Uri(url);
            NameValueCollection query = HttpUtility.ParseQueryString(uri.Query);
            var leftPart = uri.GetLeftPart(UriPartial.Path);
            return QueryHelpers.AddQueryString(leftPart, "state", query["state"]);
        }

        protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {
            string state = Options.StateDataFormat.Protect(properties);
            var parameters = new Dictionary<string, string>
            {
                ["service"] = QueryHelpers.AddQueryString(redirectUri, "state", state),
            };
            return QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, parameters);
        }

        private IEnumerable<Claim> GetXmlClaims(XDocument xdoc)
        {
            XmlNamespaceManager namespaceManager = new XmlNamespaceManager(new NameTable());
            namespaceManager.AddNamespace("cas", NamespaceName);

            return xdoc.XPathSelectElements("/cas:serviceResponse/cas:authenticationSuccess/cas:attributes//*", namespaceManager)
                .Where(x => x.Name.NamespaceName == NamespaceName)
                .Select(x => new Claim(x.Name.LocalName, x.Value));
        }

        private string GetXmlErrorMessage(XDocument xdoc)
        {
            XmlNamespaceManager namespaceManager = new XmlNamespaceManager(new NameTable());
            namespaceManager.AddNamespace("cas", NamespaceName);

            return xdoc.XPathSelectElement("/cas:serviceResponse/cas:authenticationFailure", namespaceManager)?.Value;
        }
    }
}
