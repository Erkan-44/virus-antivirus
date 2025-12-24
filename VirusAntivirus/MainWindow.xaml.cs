using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using VirusAntivirus.Models;
using VirusAntivirus.Services;

namespace VirusAntivirus
{
    public partial class MainWindow : Window
    {
        private readonly RegistryScanner _scanner;
        private readonly RegistryCleaner _cleaner;
        private List<RegistryThreat> _currentThreats;

        public MainWindow()
        {
            InitializeComponent();
            
            // Yönetici yetkilerini kontrol et
            try
            {
                SecurityChecker.CheckAdministratorRights();
            }
            catch (UnauthorizedAccessException ex)
            {
                MessageBox.Show(ex.Message, "Yetki Hatası", 
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            _scanner = new RegistryScanner();
            _cleaner = new RegistryCleaner();
            _currentThreats = new List<RegistryThreat>();
        }

        private async void ScanButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                ScanButton.IsEnabled = false;
                ScanProgressBar.Visibility = Visibility.Visible;
                StatusText.Text = "Tarama devam ediyor...";
                ThreatListView.ItemsSource = null;

                await Task.Run(() =>
                {
                    Dispatcher.Invoke(() =>
                    {
                        _currentThreats = _scanner.ScanRegistry();
                    });
                });

                ThreatListView.ItemsSource = _currentThreats;
                ThreatCountText.Text = $"({_currentThreats.Count})";
                
                UpdateStatistics();
                UpdateStatus();

                StatusText.Text = $"Tarama tamamlandı - {_currentThreats.Count} tehdit bulundu";
                LastScanText.Text = $"Son tarama: {DateTime.Now:dd.MM.yyyy HH:mm:ss}";
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Tarama sırasında hata oluştu: {ex.Message}", 
                    "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
                StatusText.Text = "Hata oluştu";
            }
            finally
            {
                ScanButton.IsEnabled = true;
                ScanProgressBar.Visibility = Visibility.Collapsed;
            }
        }

        private void ThreatListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ThreatListView.SelectedItem is RegistryThreat threat)
            {
                SelectedThreatInfo.Text = 
                    $"Tehdit Tipi: {threat.ThreatType}\n" +
                    $"Önem Derecesi: {threat.Severity}\n" +
                    $"Kayıt Yolu: {threat.RegistryPath}\n" +
                    $"Anahtar: {threat.KeyName}\n" +
                    $"Değer: {threat.Value}\n" +
                    $"Açıklama: {threat.Description}\n" +
                    $"Tespit Zamanı: {threat.DetectedAt:dd.MM.yyyy HH:mm:ss}";

                RemoveButton.IsEnabled = true;
                RestoreButton.IsEnabled = true;
            }
            else
            {
                SelectedThreatInfo.Text = "Bir tehdit seçin...";
                RemoveButton.IsEnabled = false;
                RestoreButton.IsEnabled = false;
            }
        }

        private void RemoveButton_Click(object sender, RoutedEventArgs e)
        {
            if (ThreatListView.SelectedItem is not RegistryThreat threat)
            {
                MessageBox.Show("Lütfen kaldırmak istediğiniz tehdidi seçin.", 
                    "Uyarı", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var result = MessageBox.Show(
                $"Bu tehdidi kaldırmak istediğinizden emin misiniz?\n\n" +
                $"Kayıt Yolu: {threat.RegistryPath}\n" +
                $"Anahtar: {threat.KeyName}\n" +
                $"Değer: {threat.Value}",
                "Onay", MessageBoxButton.YesNo, MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                try
                {
                    if (_cleaner.RemoveThreat(threat))
                    {
                        MessageBox.Show("Tehdit başarıyla kaldırıldı.", 
                            "Başarılı", MessageBoxButton.OK, MessageBoxImage.Information);
                        
                        _currentThreats.Remove(threat);
                        ThreatListView.ItemsSource = null;
                        ThreatListView.ItemsSource = _currentThreats;
                        ThreatCountText.Text = $"({_currentThreats.Count})";
                        UpdateStatistics();
                    }
                    else
                    {
                        MessageBox.Show("Tehdit kaldırılamadı. Yönetici yetkileri gerekli olabilir.", 
                            "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Hata: {ex.Message}", 
                        "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void RestoreButton_Click(object sender, RoutedEventArgs e)
        {
            if (ThreatListView.SelectedItem is not RegistryThreat threat)
            {
                MessageBox.Show("Lütfen geri yüklemek istediğiniz tehdidi seçin.", 
                    "Uyarı", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // Varsayılan değerleri belirle
            string defaultValue = threat.KeyName switch
            {
                "Shell" => "explorer.exe",
                "Userinit" => "C:\\Windows\\System32\\userinit.exe,",
                _ => ""
            };

            if (string.IsNullOrEmpty(defaultValue))
            {
                MessageBox.Show("Bu kayıt için varsayılan değer bilinmiyor.", 
                    "Bilgi", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var result = MessageBox.Show(
                $"Varsayılan değere geri döndürmek istediğinizden emin misiniz?\n\n" +
                $"Mevcut Değer: {threat.Value}\n" +
                $"Varsayılan Değer: {defaultValue}",
                "Onay", MessageBoxButton.YesNo, MessageBoxImage.Question);

            if (result == MessageBoxResult.Yes)
            {
                try
                {
                    if (_cleaner.RestoreDefaultValue(threat, defaultValue))
                    {
                        MessageBox.Show("Varsayılan değer başarıyla geri yüklendi.", 
                            "Başarılı", MessageBoxButton.OK, MessageBoxImage.Information);
                        
                        // Listeyi yenile
                        ScanButton_Click(sender, e);
                    }
                    else
                    {
                        MessageBox.Show("Varsayılan değer geri yüklenemedi.", 
                            "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Hata: {ex.Message}", 
                        "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ExportButton_Click(object sender, RoutedEventArgs e)
        {
            if (_currentThreats.Count == 0)
            {
                MessageBox.Show("Dışa aktarılacak tehdit bulunamadı.", 
                    "Uyarı", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                var fileName = $"ThreatReport_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
                var filePath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    fileName);

                using var writer = new StreamWriter(filePath);
                writer.WriteLine("VİRÜS ANTİVİRÜS - TEHDİT RAPORU");
                writer.WriteLine("=".PadRight(50, '='));
                writer.WriteLine($"Rapor Tarihi: {DateTime.Now:dd.MM.yyyy HH:mm:ss}");
                writer.WriteLine($"Toplam Tehdit: {_currentThreats.Count}");
                writer.WriteLine();
                writer.WriteLine();

                foreach (var threat in _currentThreats)
                {
                    writer.WriteLine($"Tehdit Tipi: {threat.ThreatType}");
                    writer.WriteLine($"Önem Derecesi: {threat.Severity}");
                    writer.WriteLine($"Kayıt Yolu: {threat.RegistryPath}");
                    writer.WriteLine($"Anahtar: {threat.KeyName}");
                    writer.WriteLine($"Değer: {threat.Value}");
                    writer.WriteLine($"Açıklama: {threat.Description}");
                    writer.WriteLine($"Tespit Zamanı: {threat.DetectedAt:dd.MM.yyyy HH:mm:ss}");
                    writer.WriteLine("-".PadRight(50, '-'));
                    writer.WriteLine();
                }

                MessageBox.Show($"Rapor başarıyla kaydedildi:\n{filePath}", 
                    "Başarılı", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Rapor kaydedilemedi: {ex.Message}", 
                    "Hata", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void UpdateStatistics()
        {
            var critical = _currentThreats.Count(t => t.Severity == ThreatSeverity.Critical);
            var high = _currentThreats.Count(t => t.Severity == ThreatSeverity.High);
            var medium = _currentThreats.Count(t => t.Severity == ThreatSeverity.Medium);
            var low = _currentThreats.Count(t => t.Severity == ThreatSeverity.Low);

            StatsText.Text = 
                $"Toplam Tehdit: {_currentThreats.Count}\n" +
                $"Kritik: {critical}\n" +
                $"Yüksek: {high}\n" +
                $"Orta: {medium}\n" +
                $"Düşük: {low}";
        }

        private void UpdateStatus()
        {
            if (_currentThreats.Count == 0)
            {
                StatusText.Text = "Tehdit bulunamadı - Sistem temiz görünüyor";
            }
            else if (_currentThreats.Any(t => t.Severity == ThreatSeverity.Critical))
            {
                StatusText.Text = "⚠️ KRİTİK TEHDİTLER TESPİT EDİLDİ!";
            }
            else
            {
                StatusText.Text = $"⚠️ {_currentThreats.Count} tehdit bulundu";
            }
        }
    }
}

