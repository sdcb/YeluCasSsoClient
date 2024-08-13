using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using System;

namespace Sdcb.AspNetCore.Authentication.YeluCasSso;

public class YeluCasSsoOptions : OAuthOptions
{
    public string YeluCasSsoEndpoint { get; set; }

    public bool ForceHttps { get; set; }

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
