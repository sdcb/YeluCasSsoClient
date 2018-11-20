using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Sdcb.AspNetCore.Authentication.YeluCasSso;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
    public static class YeluCasSsoExtensions
    {
        public static AuthenticationBuilder AddYeluCasSso(this AuthenticationBuilder builder, string yeluCasSsoEndpoint)
            => builder.AddYeluCasSso(YeluCasSsoDefaults.AuthenticationScheme, o => o.YeluCasSsoEndpoint = yeluCasSsoEndpoint);

        public static AuthenticationBuilder AddYeluCasSso(this AuthenticationBuilder builder, Action<YeluCasSsoOptions> configureOptions)
            => builder.AddYeluCasSso(YeluCasSsoDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddYeluCasSso(this AuthenticationBuilder builder, string authenticationScheme, string yeluCasSsoEndpoint)
            => builder.AddYeluCasSso(authenticationScheme, displayName: authenticationScheme, configureOptions: o => o.YeluCasSsoEndpoint = yeluCasSsoEndpoint);

        public static AuthenticationBuilder AddYeluCasSso(this AuthenticationBuilder builder, string authenticationScheme, Action<YeluCasSsoOptions> configureOptions)
            => builder.AddYeluCasSso(authenticationScheme, displayName: authenticationScheme, configureOptions: configureOptions);

        public static AuthenticationBuilder AddYeluCasSso(this AuthenticationBuilder builder, string authenticationScheme, string displayName, string yeluCasSsoEndpoint)
            => builder.AddYeluCasSso(authenticationScheme, displayName, o => o.YeluCasSsoEndpoint = yeluCasSsoEndpoint);

        public static AuthenticationBuilder AddYeluCasSso(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<YeluCasSsoOptions> configureOptions)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<YeluCasSsoOptions>, YeluCasSsoPostConfigureOptions>());
            return builder.AddScheme<YeluCasSsoOptions, YeluCasSsoHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}
