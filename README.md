# Yelu CAS SSO Client [![NuGet](https://img.shields.io/badge/nuget-1.0.5-blue.svg)](https://www.nuget.org/packages/Sdcb.AspNetCore.Authentication.YeluCasSso/)

## Integrate with ASP.NET Identity:
In `Startup.cs` `ConfigureServices` method(replace the example url with yours):
```
services.AddAuthentication().AddYeluCasSso("https://example.com/cas");
```

## Integrate with raw ASP.NET Core project:
In `Startup.cs` `ConfigureServices` method(replace the example url with yours):
```
services.AddAuthentication(o =>
{
    o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    o.DefaultChallengeScheme = YeluCasSsoDefaults.AuthenticationScheme;
}).AddCookie().AddYeluCasSso("https://example.com/cas");
```
In `Startup.cs` `Configure` method(replace the example url with yours): 
```
app.UseAuthentication();
```
