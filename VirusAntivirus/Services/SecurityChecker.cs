using System;
using System.Security.Principal;

namespace VirusAntivirus.Services
{
    public class SecurityChecker
    {
        public static bool IsRunningAsAdministrator()
        {
            try
            {
                var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        public static void CheckAdministratorRights()
        {
            if (!IsRunningAsAdministrator())
            {
                throw new UnauthorizedAccessException(
                    "Bu uygulama yönetici yetkileri gerektirir. Lütfen uygulamayı yönetici olarak çalıştırın.");
            }
        }
    }
}

