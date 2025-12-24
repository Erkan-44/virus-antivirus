# 🛡️ Virüs Antivirüs Uygulaması

Windows Registry tabanlı güvenlik tarayıcısı ve temizleme aracı. C# ve WPF kullanılarak geliştirilmiştir.

## Özellikler

- ✅ **Registry Tarama**: Windows Registry'deki zararlı kayıtları tespit eder
- ✅ **Otomatik Başlangıç Kontrolü**: Sistem başlangıcında çalışan şüpheli programları bulur
- ✅ **Tarayıcı Hijacker Tespiti**: Tarayıcı yönlendirme saldırılarını tespit eder
- ✅ **Shell Değişiklik Tespiti**: Kritik sistem kayıtlarındaki değişiklikleri bulur
- ✅ **Tehdit Temizleme**: Tespit edilen tehditleri kaldırma özelliği
- ✅ **Raporlama**: Detaylı tehdit raporlarını dışa aktarma

## Gereksinimler

- .NET 6.0 veya üzeri
- Windows 10/11
- Yönetici yetkileri (Registry erişimi için)

## Kurulum

1. Projeyi klonlayın veya indirin
2. Visual Studio 2022 veya .NET SDK ile açın
3. Projeyi derleyin:
   ```bash
   dotnet build
   ```
4. Uygulamayı çalıştırın (Yönetici olarak):
   ```bash
   dotnet run
   ```

## Kullanım

1. Uygulamayı **Yönetici olarak** çalıştırın
2. "Registry Taraması Başlat" butonuna tıklayın
3. Tespit edilen tehditleri inceleyin
4. İstediğiniz tehdidi seçip "Tehdidi Kaldır" veya "Varsayılan Değere Döndür" butonlarını kullanın
5. Raporu dışa aktarmak için "Raporu Dışa Aktar" butonunu kullanın

## Tespit Edilen Tehdit Türleri

- **StartupProgram**: Otomatik başlangıç programları
- **BrowserHijacker**: Tarayıcı yönlendirme saldırıları
- **SuspiciousValue**: Şüpheli kayıt değerleri
- **MalwareSignature**: Bilinen zararlı yazılım imzaları
- **SuspiciousPath**: Şüpheli dosya yolları

## Önemli Notlar

⚠️ **UYARI**: Bu uygulama yönetici yetkileri gerektirir ve sistem kayıtlarını değiştirebilir. Kullanmadan önce sistem yedeği alın.

⚠️ Bu uygulama eğitim amaçlıdır ve profesyonel bir antivirüs yazılımının yerini tutmaz.

## Lisans

Bu proje eğitim amaçlıdır.

## Geliştirici Notları

- Registry tarama işlemleri asenkron olarak çalışır
- Tehdit seviyeleri: Critical, High, Medium, Low
- Tüm işlemler loglanır ve raporlanabilir

