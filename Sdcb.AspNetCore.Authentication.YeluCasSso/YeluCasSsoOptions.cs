using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Sdcb.AspNetCore.Authentication.YeluCasSso
{
    public class YeluCasSsoOptions : OAuthOptions
    {
        public string YeluCasSsoEndpoint { get; set; }

        public YeluCasSsoOptions()
        {
            CallbackPath = new PathString("/yelu-cas-sso/callback");
            Events = new YeluCasSsoEvents();
            ClientId = "Do not apply";
            ClientSecret = "Do not apply";
            TokenEndpoint = "Do not apply";
        }

        public override void Validate()
        {
            base.Validate();

            if (String.IsNullOrEmpty(YeluCasSsoEndpoint))
            {
                throw new ArgumentException($"{nameof(YeluCasSsoEndpoint)} must be provided.");
            }
        }

        public new YeluCasSsoEvents Events
        {
            get { return (YeluCasSsoEvents)base.Events; }
            set { base.Events = value; }
        }
    }
}
