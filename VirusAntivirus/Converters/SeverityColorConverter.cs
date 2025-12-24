using System;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Media;
using VirusAntivirus.Models;

namespace VirusAntivirus.Converters
{
    public class SeverityColorConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is ThreatSeverity severity)
            {
                return severity switch
                {
                    ThreatSeverity.Critical => new SolidColorBrush(Colors.Red),
                    ThreatSeverity.High => new SolidColorBrush(Colors.Orange),
                    ThreatSeverity.Medium => new SolidColorBrush(Colors.Yellow),
                    ThreatSeverity.Low => new SolidColorBrush(Colors.Green),
                    _ => new SolidColorBrush(Colors.Gray)
                };
            }
            return new SolidColorBrush(Colors.Gray);
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}

