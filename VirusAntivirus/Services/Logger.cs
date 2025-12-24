using System;
using System.IO;

namespace VirusAntivirus.Services
{
    public class Logger
    {
        private readonly string _logFilePath;

        public Logger()
        {
            var logDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "VirusAntivirus",
                "Logs"
            );

            Directory.CreateDirectory(logDirectory);
            _logFilePath = Path.Combine(logDirectory, $"log_{DateTime.Now:yyyyMMdd}.txt");
        }

        public void LogInfo(string message)
        {
            WriteLog("INFO", message);
        }

        public void LogWarning(string message)
        {
            WriteLog("WARNING", message);
        }

        public void LogError(string message, Exception? ex = null)
        {
            var errorMessage = ex != null ? $"{message} - {ex.Message}" : message;
            WriteLog("ERROR", errorMessage);
        }

        public void LogThreat(string threatInfo)
        {
            WriteLog("THREAT", threatInfo);
        }

        private void WriteLog(string level, string message)
        {
            try
            {
                var logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{level}] {message}";
                File.AppendAllText(_logFilePath, logEntry + Environment.NewLine);
            }
            catch
            {
                // Log yazma hatası durumunda sessizce devam et
            }
        }
    }
}

