using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Win32;
using VirusAntivirus.Models;

namespace VirusAntivirus.Services
{
    public class RegistryScanner
    {
        private readonly List<string> _malwareSignatures;
        private readonly List<string> _suspiciousPaths;
        private readonly List<string> _suspiciousExtensions;
        private readonly Logger _logger;

        public RegistryScanner()
        {
            _logger = new Logger();
            _malwareSignatures = new List<string>
            {
                "cmd.exe /c",
                "powershell.exe -enc",
                "rundll32.exe",
                "wscript.exe",
                "cscript.exe",
                "mshta.exe",
                "regsvr32.exe",
                "certutil.exe",
                "bitsadmin.exe"
            };

            _suspiciousPaths = new List<string>
            {
                @"%TEMP%",
                @"%APPDATA%",
                @"%LOCALAPPDATA%\Temp",
                @"C:\Windows\Temp",
                @"C:\Users\Public"
            };

            _suspiciousExtensions = new List<string>
            {
                ".bat", ".cmd", ".vbs", ".js", ".jar", ".scr", ".pif", ".com"
            };
        }

        public List<RegistryThreat> ScanRegistry()
        {
            _logger.LogInfo("Registry taraması başlatıldı");
            var threats = new List<RegistryThreat>();

            // Otomatik başlangıç programlarını tara
            _logger.LogInfo("Otomatik başlangıç programları taranıyor...");
            threats.AddRange(ScanStartupPrograms());

            // Run anahtarlarını tara
            threats.AddRange(ScanRunKeys());

            // Browser hijacker kontrolü
            threats.AddRange(ScanBrowserHijackers());

            // Shell açılış komutlarını kontrol et
            threats.AddRange(ScanShellKeys());

            // Context Menu Handlers kontrolü
            threats.AddRange(ScanContextMenuHandlers());

            // File Associations kontrolü
            threats.AddRange(ScanFileAssociations());

            // Services kontrolü
            threats.AddRange(ScanServices());

            _logger.LogInfo($"Tarama tamamlandı. Toplam {threats.Count} tehdit bulundu.");
            return threats;
        }

        private List<RegistryThreat> ScanStartupPrograms()
        {
            var threats = new List<RegistryThreat>();
            var startupKeys = new[]
            {
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices",
                @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
            };

            foreach (var keyPath in startupKeys)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                    if (key == null) continue;

                    foreach (var valueName in key.GetValueNames())
                    {
                        var value = key.GetValue(valueName)?.ToString() ?? string.Empty;
                        
                        if (IsSuspicious(value))
                        {
                            threats.Add(new RegistryThreat
                            {
                                RegistryPath = keyPath,
                                KeyName = valueName,
                                Value = value,
                                ThreatType = ThreatType.StartupProgram,
                                Severity = DetermineSeverity(value),
                                Description = $"Şüpheli otomatik başlangıç programı tespit edildi: {valueName}"
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    // Hata durumunda devam et
                    System.Diagnostics.Debug.WriteLine($"Hata: {keyPath} - {ex.Message}");
                }
            }

            return threats;
        }

        private List<RegistryThreat> ScanRunKeys()
        {
            var threats = new List<RegistryThreat>();
            var runKeys = new[]
            {
                Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                Registry.CurrentUser.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
                Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
                Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
            };

            foreach (var key in runKeys)
            {
                if (key == null) continue;

                try
                {
                    foreach (var valueName in key.GetValueNames())
                    {
                        var value = key.GetValue(valueName)?.ToString() ?? string.Empty;
                        
                        if (IsSuspicious(value))
                        {
                            threats.Add(new RegistryThreat
                            {
                                RegistryPath = key.Name,
                                KeyName = valueName,
                                Value = value,
                                ThreatType = ThreatType.StartupProgram,
                                Severity = DetermineSeverity(value),
                                Description = $"Şüpheli Run anahtarı: {valueName}"
                            });
                        }
                    }
                }
                finally
                {
                    key.Close();
                }
            }

            return threats;
        }

        private List<RegistryThreat> ScanBrowserHijackers()
        {
            var threats = new List<RegistryThreat>();
            var browserKeys = new[]
            {
                @"SOFTWARE\Microsoft\Internet Explorer\Main",
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
                @"SOFTWARE\Policies\Microsoft\Internet Explorer"
            };

            foreach (var keyPath in browserKeys)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                    if (key == null) continue;

                    var suspiciousValues = new[] { "Start Page", "Search Page", "Default_Page_URL" };
                    
                    foreach (var valueName in suspiciousValues)
                    {
                        var value = key.GetValue(valueName)?.ToString() ?? string.Empty;
                        
                        if (!string.IsNullOrEmpty(value) && 
                            (value.Contains("search") || value.Contains("redirect") || 
                             !value.StartsWith("http://") && !value.StartsWith("https://")))
                        {
                            threats.Add(new RegistryThreat
                            {
                                RegistryPath = keyPath,
                                KeyName = valueName,
                                Value = value,
                                ThreatType = ThreatType.BrowserHijacker,
                                Severity = ThreatSeverity.Medium,
                                Description = $"Tarayıcı yönlendirme şüphesi: {valueName}"
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Hata: {keyPath} - {ex.Message}");
                }
            }

            return threats;
        }

        private List<RegistryThreat> ScanShellKeys()
        {
            var threats = new List<RegistryThreat>();
            var shellKeyPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";

            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(shellKeyPath);
                if (key == null) return threats;

                var shellValue = key.GetValue("Shell")?.ToString() ?? string.Empty;
                var userInitValue = key.GetValue("Userinit")?.ToString() ?? string.Empty;

                if (!string.IsNullOrEmpty(shellValue) && shellValue != "explorer.exe")
                {
                    threats.Add(new RegistryThreat
                    {
                        RegistryPath = shellKeyPath,
                        KeyName = "Shell",
                        Value = shellValue,
                        ThreatType = ThreatType.SuspiciousValue,
                        Severity = ThreatSeverity.Critical,
                        Description = "Shell değeri değiştirilmiş - kritik tehdit!"
                    });
                }

                if (!string.IsNullOrEmpty(userInitValue) && 
                    (userInitValue.Contains(",") || userInitValue.Split(' ').Length > 1))
                {
                    threats.Add(new RegistryThreat
                    {
                        RegistryPath = shellKeyPath,
                        KeyName = "Userinit",
                        Value = userInitValue,
                        ThreatType = ThreatType.SuspiciousValue,
                        Severity = ThreatSeverity.High,
                        Description = "Userinit değeri şüpheli görünüyor"
                    });
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Hata: {shellKeyPath} - {ex.Message}");
            }

            return threats;
        }

        private bool IsSuspicious(string value)
        {
            if (string.IsNullOrEmpty(value)) return false;

            value = value.ToLower();

            // Şüpheli yollar kontrolü
            foreach (var suspiciousPath in _suspiciousPaths)
            {
                if (value.Contains(suspiciousPath.ToLower().Replace("%", "")))
                {
                    return true;
                }
            }

            // Şüpheli uzantılar kontrolü
            foreach (var ext in _suspiciousExtensions)
            {
                if (value.Contains(ext))
                {
                    return true;
                }
            }

            // Malware imzaları kontrolü
            foreach (var signature in _malwareSignatures)
            {
                if (value.Contains(signature.ToLower()))
                {
                    return true;
                }
            }

            // Şüpheli karakterler
            if (value.Contains("cmd.exe") || value.Contains("powershell") || 
                value.Contains("rundll32") || value.Contains("wscript"))
            {
                return true;
            }

            return false;
        }

        private ThreatSeverity DetermineSeverity(string value)
        {
            value = value.ToLower();

            if (value.Contains("cmd.exe") || value.Contains("powershell") || 
                value.Contains("rundll32") || value.Contains("certutil"))
            {
                return ThreatSeverity.Critical;
            }

            if (value.Contains(".bat") || value.Contains(".vbs") || value.Contains(".js"))
            {
                return ThreatSeverity.High;
            }

            if (value.Contains("%temp%") || value.Contains("%appdata%"))
            {
                return ThreatSeverity.Medium;
            }

            return ThreatSeverity.Low;
        }

        private List<RegistryThreat> ScanContextMenuHandlers()
        {
            var threats = new List<RegistryThreat>();
            var contextMenuKeys = new[]
            {
                @"SOFTWARE\Classes\*\shellex\ContextMenuHandlers",
                @"SOFTWARE\Classes\Directory\shellex\ContextMenuHandlers",
                @"SOFTWARE\Classes\Folder\shellex\ContextMenuHandlers"
            };

            foreach (var keyPath in contextMenuKeys)
            {
                try
                {
                    using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                    if (key == null) continue;

                    foreach (var subKeyName in key.GetSubKeyNames())
                    {
                        using var subKey = key.OpenSubKey(subKeyName);
                        if (subKey == null) continue;

                        var clsid = subKey.GetValue("")?.ToString() ?? string.Empty;
                        if (!string.IsNullOrEmpty(clsid) && IsSuspicious(clsid))
                        {
                            threats.Add(new RegistryThreat
                            {
                                RegistryPath = keyPath,
                                KeyName = subKeyName,
                                Value = clsid,
                                ThreatType = ThreatType.SuspiciousValue,
                                Severity = ThreatSeverity.Medium,
                                Description = $"Şüpheli bağlam menüsü işleyicisi: {subKeyName}"
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Hata: {keyPath} - {ex.Message}");
                }
            }

            return threats;
        }

        private List<RegistryThreat> ScanFileAssociations()
        {
            var threats = new List<RegistryThreat>();
            var suspiciousExtensions = new[] { ".exe", ".bat", ".cmd", ".vbs", ".js", ".scr", ".pif" };

            foreach (var ext in suspiciousExtensions)
            {
                try
                {
                    var keyPath = $@"SOFTWARE\Classes\{ext}";
                    using var key = Registry.LocalMachine.OpenSubKey(keyPath);
                    if (key == null) continue;

                    var defaultValue = key.GetValue("")?.ToString() ?? string.Empty;
                    if (!string.IsNullOrEmpty(defaultValue))
                    {
                        var commandKeyPath = $@"SOFTWARE\Classes\{defaultValue}\shell\open\command";
                        using var commandKey = Registry.LocalMachine.OpenSubKey(commandKeyPath);
                        if (commandKey != null)
                        {
                            var command = commandKey.GetValue("")?.ToString() ?? string.Empty;
                            if (IsSuspicious(command))
                            {
                                threats.Add(new RegistryThreat
                                {
                                    RegistryPath = commandKeyPath,
                                    KeyName = ext,
                                    Value = command,
                                    ThreatType = ThreatType.UnknownExtension,
                                    Severity = ThreatSeverity.High,
                                    Description = $"Şüpheli dosya ilişkilendirmesi: {ext}"
                                });
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"Hata: {ext} - {ex.Message}");
                }
            }

            return threats;
        }

        private List<RegistryThreat> ScanServices()
        {
            var threats = new List<RegistryThreat>();
            var servicesKeyPath = @"SYSTEM\CurrentControlSet\Services";

            try
            {
                using var servicesKey = Registry.LocalMachine.OpenSubKey(servicesKeyPath);
                if (servicesKey == null) return threats;

                foreach (var serviceName in servicesKey.GetSubKeyNames())
                {
                    try
                    {
                        using var serviceKey = servicesKey.OpenSubKey(serviceName);
                        if (serviceKey == null) continue;

                        var imagePath = serviceKey.GetValue("ImagePath")?.ToString() ?? string.Empty;
                        if (IsSuspicious(imagePath))
                        {
                            threats.Add(new RegistryThreat
                            {
                                RegistryPath = $"{servicesKeyPath}\\{serviceName}",
                                KeyName = "ImagePath",
                                Value = imagePath,
                                ThreatType = ThreatType.HiddenProcess,
                                Severity = DetermineSeverity(imagePath),
                                Description = $"Şüpheli Windows servisi: {serviceName}"
                            });
                        }
                    }
                    catch
                    {
                        // Servis erişim hatası, devam et
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Hata: {servicesKeyPath} - {ex.Message}");
            }

            return threats;
        }
    }
}

