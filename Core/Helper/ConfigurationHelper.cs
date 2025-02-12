using Microsoft.Extensions.Configuration;

namespace Core.Helper
{
    public class ConfigurationHelper
    {
        public static IConfiguration config;
        public static void Initialize(IConfiguration Configuration)
        {
            config = Configuration;
        }

    }
}
