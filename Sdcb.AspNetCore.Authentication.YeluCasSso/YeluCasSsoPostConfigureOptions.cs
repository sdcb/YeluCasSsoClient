using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using System.Net.Http;

namespace Sdcb.AspNetCore.Authentication.YeluCasSso;

public partial class YeluCasSsoPostConfigureOptions(IDataProtectionProvider dataProtection) : IPostConfigureOptions<YeluCasSsoOptions>
{
    private readonly IDataProtectionProvider _dp = dataProtection;

    public void PostConfigure(string name, YeluCasSsoOptions options)
    {
        options.DataProtectionProvider = options.DataProtectionProvider ?? _dp;
        if (options.Backchannel == null)
        {
            options.Backchannel = new HttpClient(options.BackchannelHttpHandler ?? new HttpClientHandler());
            options.Backchannel.DefaultRequestHeaders.UserAgent.ParseAdd("Microsoft ASP.NET Core YeluCasSso handler");
            options.Backchannel.Timeout = options.BackchannelTimeout;
            options.Backchannel.MaxResponseContentBufferSize = 1024 * 1024 * 10; // 10 MB
        }

        if (options.StateDataFormat == null)
        {
            IDataProtector dataProtector = options.DataProtectionProvider.CreateProtector(
                typeof(YeluCasSsoHandler).FullName, name, "v1");
            options.StateDataFormat = new PropertiesDataFormat(dataProtector);
        }

        if (options.AuthorizationEndpoint == null)
        {
            options.AuthorizationEndpoint = $"{options.YeluCasSsoEndpoint}/login";
        }
        
        if (options.UserInformationEndpoint == null)
        {
            options.UserInformationEndpoint = $"{options.YeluCasSsoEndpoint}/serviceValidate";
        }
    }
}
