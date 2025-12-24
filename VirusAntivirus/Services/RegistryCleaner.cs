using System;
using System.IO;
using Microsoft.Win32;
using VirusAntivirus.Models;

namespace VirusAntivirus.Services
{
    public class RegistryCleaner
    {
        private readonly Logger _logger;

        public RegistryCleaner()
        {
            _logger = new Logger();
        }
        public bool RemoveThreat(RegistryThreat threat)
        {
            try
            {
                var keyPath = threat.RegistryPath;
                var valueName = threat.KeyName;

                // HKEY_LOCAL_MACHINE veya HKEY_CURRENT_USER kontrolü
                RegistryKey? baseKey = null;
                string subKeyPath = keyPath;

                if (keyPath.StartsWith(@"SOFTWARE\"))
                {
                    if (keyPath.Contains(@"HKEY_CURRENT_USER") || 
                        keyPath.Contains(@"CurrentVersion\Run") && 
                        !keyPath.Contains(@"HKEY_LOCAL_MACHINE"))
                    {
                        baseKey = Registry.CurrentUser;
                        subKeyPath = keyPath.Replace(@"HKEY_CURRENT_USER\", "").Replace(@"SOFTWARE\", "");
                    }
                    else
                    {
                        baseKey = Registry.LocalMachine;
                        subKeyPath = keyPath.Replace(@"HKEY_LOCAL_MACHINE\", "").Replace(@"SOFTWARE\", "");
                    }
                }
                else
                {
                    baseKey = Registry.LocalMachine;
                }

                using var key = baseKey?.OpenSubKey(subKeyPath, true);
                if (key != null)
                {
                    _logger.LogInfo($"Tehdit kaldırılıyor: {threat.RegistryPath}\\{threat.KeyName}");
                    key.DeleteValue(valueName, false);
                    _logger.LogThreat($"Tehdit kaldırıldı: {threat.RegistryPath}\\{threat.KeyName} = {threat.Value}");
                    return true;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Temizleme hatası: {ex.Message}");
                return false;
            }

            return false;
        }

        public bool RestoreDefaultValue(RegistryThreat threat, string defaultValue)
        {
            try
            {
                var keyPath = threat.RegistryPath;
                var valueName = threat.KeyName;

                RegistryKey? baseKey = Registry.LocalMachine;
                string subKeyPath = keyPath;

                if (keyPath.StartsWith(@"SOFTWARE\"))
                {
                    subKeyPath = keyPath.Replace(@"HKEY_LOCAL_MACHINE\", "").Replace(@"SOFTWARE\", "");
                }

                using var key = baseKey?.OpenSubKey(subKeyPath, true);
                if (key != null)
                {
                    _logger.LogInfo($"Varsayılan değer geri yükleniyor: {threat.RegistryPath}\\{threat.KeyName}");
                    key.SetValue(valueName, defaultValue);
                    _logger.LogInfo($"Değer geri yüklendi: {threat.RegistryPath}\\{threat.KeyName} = {defaultValue}");
                    return true;
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Varsayılan değer geri yükleme hatası: {ex.Message}");
                return false;
            }

            return false;
        }

        public bool BackupRegistryKey(string keyPath)
        {
            try
            {
                // Registry yedeği için basit bir yaklaşım
                // Gerçek uygulamada daha gelişmiş yedekleme kullanılabilir
                var backupPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    "RegistryBackups",
                    $"{DateTime.Now:yyyyMMdd_HHmmss}_{keyPath.Replace(@"\", "_")}.reg"
                );

                Directory.CreateDirectory(Path.GetDirectoryName(backupPath)!);

                // Registry export komutu kullanılabilir
                // reg export "keyPath" "backupPath" /y
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}

