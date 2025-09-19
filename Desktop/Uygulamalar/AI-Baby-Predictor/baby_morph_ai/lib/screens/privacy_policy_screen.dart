import 'package:flutter/material.dart';
import '../constants/app_theme.dart';
import '../flutter_gen/gen_l10n/app_localizations.dart';

class PrivacyPolicyScreen extends StatelessWidget {
  const PrivacyPolicyScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    
    return Scaffold(
      appBar: AppBar(
        title: Text(l10n.privacyPolicy),
        centerTitle: true,
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Header
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                gradient: AppTheme.primaryGradient,
                borderRadius: BorderRadius.circular(16),
              ),
              child: Column(
                children: [
                  const Icon(
                    Icons.security,
                    color: Colors.white,
                    size: 40,
                  ),
                  const SizedBox(height: 12),
                  Text(
                    l10n.privacyPolicy,
                    style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                      color: Colors.white,
                      fontWeight: FontWeight.bold,
                    ),
                    textAlign: TextAlign.center,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'Son güncelleme: ${DateTime.now().day}/${DateTime.now().month}/${DateTime.now().year}',
                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                      color: Colors.white.withOpacity(0.8),
                    ),
                  ),
                ],
              ),
            ),
            
            const SizedBox(height: 24),
            
            // Content sections
            _buildSection(
              context,
              'Genel Bilgi',
              'BabyMorph AI uygulaması, kullanıcıların anne ve baba fotoğraflarından yapay zeka teknolojisi kullanarak eğlence amaçlı bebek tahminleri oluşturur. Bu gizlilik politikası, kişisel verilerinizin nasıl toplandığını, kullanıldığını ve korunduğunu açıklar.',
            ),
            
            _buildSection(
              context,
              'Toplanan Veriler',
              '• Fotoğraflar: Yalnızca işleme amacıyla geçici olarak\n• Cihaz bilgileri: Uygulama performansı için\n• Kullanım istatistikleri: Hizmet iyileştirme için\n• Firebase Analytics verileri: Anonim kullanım analizi',
            ),
            
            _buildSection(
              context,
              'Veri Kullanımı',
              'Verileriniz yalnızca aşağıdaki amaçlar için kullanılır:\n• AI bebek tahmini oluşturma\n• Uygulama performansını iyileştirme\n• Teknik destek sağlama\n• Yasal yükümlülükleri yerine getirme',
            ),
            
            _buildSection(
              context,
              'Veri Güvenliği',
              '• Tüm fotoğraflar işleme sonrası otomatik silinir\n• Veriler şifreleme ile korunur\n• Firebase güvenlik kuralları uygulanır\n• Üçüncü taraflarla veri paylaşımı yapılmaz',
            ),
            
            _buildSection(
              context,
              'Fotoğraf Politikası',
              '• Fotoğraflar yalnızca AI işleme için kullanılır\n• İşlem tamamlandıktan sonra sunuculardan silinir\n• Fotoğraflar depolanmaz veya arşivlenmez\n• Kullanıcı izni olmadan paylaşılmaz',
            ),
            
            _buildSection(
              context,
              'Üçüncü Taraf Hizmetler',
              'Uygulama aşağıdaki üçüncü taraf hizmetleri kullanır:\n• Firebase (Google): Veri depolama ve analitik\n• Google AdMob: Reklam gösterimi\n• Hugging Face: AI model hizmetleri',
            ),
            
            _buildSection(
              context,
              'Çocukların Gizliliği',
              'Uygulamamız 13 yaş altındaki çocuklardan bilerek kişisel bilgi toplamaz. Ebeveynler çocuklarının uygulamayı kullanımını denetlemelidir.',
            ),
            
            _buildSection(
              context,
              'İletişim',
              'Gizlilik politikası hakkında sorularınız için:\nE-posta: privacy@babymorph.ai\nWeb: www.babymorph.ai/privacy',
            ),
            
            const SizedBox(height: 24),
            
            // Disclaimer
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.orange.shade50,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(
                  color: Colors.orange.shade200,
                ),
              ),
              child: Column(
                children: [
                  Icon(
                    Icons.info_outline,
                    color: Colors.orange.shade700,
                    size: 24,
                  ),
                  const SizedBox(height: 8),
                  Text(
                    l10n.forEntertainment,
                    style: TextStyle(
                      color: Colors.orange.shade700,
                      fontWeight: FontWeight.w600,
                      fontSize: 14,
                    ),
                    textAlign: TextAlign.center,
                  ),
                ],
              ),
            ),
            
            const SizedBox(height: 20),
          ],
        ),
      ),
    );
  }

  Widget _buildSection(BuildContext context, String title, String content) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            title,
            style: Theme.of(context).textTheme.titleLarge?.copyWith(
              fontWeight: FontWeight.w600,
              color: AppTheme.primaryColor,
            ),
          ),
          const SizedBox(height: 8),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: AppTheme.cardColor,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(
                color: AppTheme.primaryColor.withOpacity(0.1),
              ),
            ),
            child: Text(
              content,
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                height: 1.5,
                color: AppTheme.textPrimaryColor,
              ),
            ),
          ),
        ],
      ),
    );
  }
}