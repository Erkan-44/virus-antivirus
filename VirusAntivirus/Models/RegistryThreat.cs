namespace VirusAntivirus.Models
{
    public class RegistryThreat
    {
        public string RegistryPath { get; set; } = string.Empty;
        public string KeyName { get; set; } = string.Empty;
        public string Value { get; set; } = string.Empty;
        public ThreatType ThreatType { get; set; }
        public ThreatSeverity Severity { get; set; }
        public string Description { get; set; } = string.Empty;
        public DateTime DetectedAt { get; set; } = DateTime.Now;
    }

    public enum ThreatType
    {
        StartupProgram,
        SuspiciousPath,
        BrowserHijacker,
        MalwareSignature,
        SuspiciousValue,
        UnknownExtension,
        HiddenProcess
    }

    public enum ThreatSeverity
    {
        Low,
        Medium,
        High,
        Critical
    }
}

