using Microsoft.AspNetCore.Authentication.OAuth;

namespace Sdcb.AspNetCore.Authentication.YeluCasSso
{
    public static class YeluCasSsoDefaults
    {
        public const string AuthenticationScheme = "YeluCasSso";
    }

    public static class CasConstants
    {
        public const string Id = "cas:id";
        public const string Name = "cas:name";
        public const string Email = "cas:email";
        public const string Gender = "cas:gender";
        public const string Phone = "cas:phone";
        public const string JobNumber = "cas:jobNumber";
    }
}
