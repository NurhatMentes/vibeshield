import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:provider/provider.dart';
import 'package:share_plus/share_plus.dart';

import '../services/ai_service.dart';
import '../services/premium_service.dart';
import '../constants/app_theme.dart';
import '../flutter_gen/gen_l10n/app_localizations.dart';

class ResultScreen extends StatelessWidget {
  const ResultScreen({super.key});

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    
    return Scaffold(
      appBar: AppBar(
        title: Text(l10n.appTitle),
        centerTitle: true,
        actions: [
          Consumer<AIService>(
            builder: (context, aiService, child) {
              if (aiService.resultImageUrl != null) {
                return PopupMenuButton<String>(
                  onSelected: (value) {
                    if (value == 'save') {
                      _saveImage(context, aiService.resultImageUrl!);
                    } else if (value == 'share') {
                      _shareImage(context, aiService.resultImageUrl!);
                    }
                  },
                  itemBuilder: (context) => [
                    PopupMenuItem(
                      value: 'save',
                      child: Row(
                        children: [
                          const Icon(Icons.download),
                          const SizedBox(width: 8),
                          Text(l10n.save),
                        ],
                      ),
                    ),
                    PopupMenuItem(
                      value: 'share',
                      child: Row(
                        children: [
                          const Icon(Icons.share),
                          const SizedBox(width: 8),
                          Text(l10n.share),
                        ],
                      ),
                    ),
                  ],
                );
              }
              return const SizedBox();
            },
          ),
        ],
      ),
      body: Consumer<AIService>(
        builder: (context, aiService, child) {
          if (aiService.isProcessing) {
            return _buildLoadingView(context);
          } else if (aiService.error != null) {
            return _buildErrorView(context, aiService.error!);
          } else if (aiService.resultImageUrl != null) {
            return _buildResultView(context, aiService.resultImageUrl!);
          } else {
            return _buildEmptyView(context);
          }
        },
      ),
    );
  }

  Widget _buildLoadingView(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Container(
            width: 120,
            height: 120,
            decoration: BoxDecoration(
              color: AppTheme.primaryColor.withOpacity(0.1),
              shape: BoxShape.circle,
            ),
            child: const Center(
              child: CircularProgressIndicator(
                strokeWidth: 4,
                valueColor: AlwaysStoppedAnimation<Color>(AppTheme.primaryColor),
              ),
            ),
          ).animate().scale(
            duration: 1000.ms,
            curve: Curves.easeInOut,
          ).then().shake(duration: 500.ms),
          
          const SizedBox(height: 24),
          
          Text(
            l10n.processing,
            style: Theme.of(context).textTheme.headlineSmall?.copyWith(
              fontWeight: FontWeight.w600,
              color: AppTheme.textPrimaryColor,
            ),
          ).animate().fadeIn(duration: 600.ms, delay: 200.ms),
          
          const SizedBox(height: 12),
          
          Text(
            'AI bebeğinizi oluşturuyor...',
            style: Theme.of(context).textTheme.bodyLarge?.copyWith(
              color: AppTheme.textSecondaryColor,
            ),
            textAlign: TextAlign.center,
          ).animate().fadeIn(duration: 600.ms, delay: 400.ms),
          
          const SizedBox(height: 40),
          
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 40),
            child: LinearProgressIndicator(
              backgroundColor: AppTheme.primaryColor.withOpacity(0.2),
              valueColor: const AlwaysStoppedAnimation<Color>(AppTheme.primaryColor),
            ),
          ).animate().fadeIn(duration: 600.ms, delay: 600.ms),
        ],
      ),
    );
  }

  Widget _buildErrorView(BuildContext context, String error) {
    final l10n = AppLocalizations.of(context)!;
    
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
              width: 100,
              height: 100,
              decoration: BoxDecoration(
                color: Colors.red.withOpacity(0.1),
                shape: BoxShape.circle,
              ),
              child: const Icon(
                Icons.error_outline,
                size: 50,
                color: Colors.red,
              ),
            ).animate().scale(duration: 600.ms, curve: Curves.bounceOut),
            
            const SizedBox(height: 24),
            
            Text(
              l10n.error,
              style: Theme.of(context).textTheme.headlineSmall?.copyWith(
                fontWeight: FontWeight.w600,
                color: Colors.red,
              ),
            ).animate().fadeIn(duration: 600.ms, delay: 200.ms),
            
            const SizedBox(height: 12),
            
            Text(
              error,
              style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                color: AppTheme.textSecondaryColor,
              ),
              textAlign: TextAlign.center,
            ).animate().fadeIn(duration: 600.ms, delay: 400.ms),
            
            const SizedBox(height: 32),
            
            ElevatedButton.icon(
              onPressed: () => Navigator.of(context).pop(),
              icon: const Icon(Icons.arrow_back),
              label: const Text('Geri Dön'),
              style: ElevatedButton.styleFrom(
                padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
              ),
            ).animate().fadeIn(duration: 600.ms, delay: 600.ms),
          ],
        ),
      ),
    );
  }

  Widget _buildResultView(BuildContext context, String imageUrl) {
    final l10n = AppLocalizations.of(context)!;
    
    return SingleChildScrollView(
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Success message
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              gradient: AppTheme.primaryGradient,
              borderRadius: BorderRadius.circular(16),
            ),
            child: Row(
              children: [
                const Icon(
                  Icons.celebration,
                  color: Colors.white,
                  size: 24,
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    'Bebeğiniz hazır! 🎉',
                    style: Theme.of(context).textTheme.titleLarge?.copyWith(
                      color: Colors.white,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
              ],
            ),
          ).animate().slideY(
            begin: -0.3,
            end: 0,
            duration: 600.ms,
            curve: Curves.easeOut,
          ).fadeIn(duration: 600.ms),
          
          const SizedBox(height: 24),
          
          // Result image
          Hero(
            tag: 'baby_result',
            child: Container(
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(20),
                boxShadow: [
                  BoxShadow(
                    color: AppTheme.primaryColor.withOpacity(0.2),
                    blurRadius: 20,
                    offset: const Offset(0, 10),
                  ),
                ],
              ),
              child: ClipRRect(
                borderRadius: BorderRadius.circular(20),
                child: AspectRatio(
                  aspectRatio: 1,
                  child: imageUrl.startsWith('http')
                      ? Image.network(
                          imageUrl,
                          fit: BoxFit.cover,
                          errorBuilder: (context, error, stackTrace) {
                            return Container(
                              color: AppTheme.secondaryColor,
                              child: const Icon(
                                Icons.image_not_supported,
                                size: 50,
                                color: AppTheme.textSecondaryColor,
                              ),
                            );
                          },
                        )
                      : Container(
                          color: AppTheme.secondaryColor,
                          child: const Center(
                            child: Text(
                              'Demo Bebek Sonucu',
                              style: TextStyle(
                                fontSize: 18,
                                fontWeight: FontWeight.w600,
                                color: AppTheme.textPrimaryColor,
                              ),
                            ),
                          ),
                        ),
                ),
              ),
            ),
          ).animate().scale(
            duration: 800.ms,
            delay: 200.ms,
            curve: Curves.elasticOut,
          ),
          
          const SizedBox(height: 24),
          
          // Action buttons
          Row(
            children: [
              Expanded(
                child: ElevatedButton.icon(
                  onPressed: () => _saveImage(context, imageUrl),
                  icon: const Icon(Icons.download),
                  label: Text(l10n.save),
                  style: ElevatedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 16),
                  ),
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: () => _shareImage(context, imageUrl),
                  icon: const Icon(Icons.share),
                  label: Text(l10n.share),
                  style: OutlinedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 16),
                  ),
                ),
              ),
            ],
          ).animate().slideY(
            begin: 0.3,
            end: 0,
            duration: 600.ms,
            delay: 600.ms,
            curve: Curves.easeOut,
          ).fadeIn(duration: 600.ms, delay: 600.ms),
          
          const SizedBox(height: 24),
          
          // Try again button
          SizedBox(
            width: double.infinity,
            child: TextButton.icon(
              onPressed: () {
                Provider.of<AIService>(context, listen: false).clearResult();
                Navigator.of(context).pop();
              },
              icon: const Icon(Icons.refresh),
              label: const Text('Yeni Deneme Yap'),
              style: TextButton.styleFrom(
                padding: const EdgeInsets.symmetric(vertical: 16),
              ),
            ),
          ).animate().fadeIn(duration: 600.ms, delay: 800.ms),
          
          const SizedBox(height: 16),
          
          // Premium promotion (if not premium)
          Consumer<PremiumService>(
            builder: (context, premiumService, child) {
              if (!premiumService.isPremium) {
                return Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: Colors.amber.shade50,
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                      color: Colors.amber.shade200,
                    ),
                  ),
                  child: Column(
                    children: [
                      Row(
                        children: [
                          Icon(
                            Icons.star,
                            color: Colors.amber.shade700,
                            size: 20,
                          ),
                          const SizedBox(width: 8),
                          Text(
                            'Premium ile daha kaliteli sonuçlar!',
                            style: TextStyle(
                              color: Colors.amber.shade700,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 8),
                      Text(
                        'Yüksek çözünürlük ve reklamsız deneyim için Premium\'a geçin.',
                        style: TextStyle(
                          color: Colors.amber.shade700,
                          fontSize: 12,
                        ),
                      ),
                    ],
                  ),
                ).animate().fadeIn(duration: 600.ms, delay: 1000.ms);
              }
              return const SizedBox();
            },
          ),
          
          const SizedBox(height: 20),
          
          // Entertainment disclaimer
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.grey.shade100,
              borderRadius: BorderRadius.circular(8),
            ),
            child: Text(
              l10n.forEntertainment,
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                color: AppTheme.textSecondaryColor,
                fontSize: 11,
              ),
              textAlign: TextAlign.center,
            ),
          ).animate().fadeIn(duration: 600.ms, delay: 1200.ms),
        ],
      ),
    );
  }

  Widget _buildEmptyView(BuildContext context) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(
            Icons.image_not_supported,
            size: 80,
            color: AppTheme.textSecondaryColor,
          ),
          const SizedBox(height: 16),
          Text(
            'Henüz sonuç yok',
            style: Theme.of(context).textTheme.titleLarge?.copyWith(
              color: AppTheme.textSecondaryColor,
            ),
          ),
          const SizedBox(height: 24),
          ElevatedButton.icon(
            onPressed: () => Navigator.of(context).pop(),
            icon: const Icon(Icons.arrow_back),
            label: const Text('Geri Dön'),
          ),
        ],
      ),
    );
  }

  Future<void> _saveImage(BuildContext context, String imageUrl) async {
    try {
      final l10n = AppLocalizations.of(context)!;
      
      // Show loading
      showDialog(
        context: context,
        barrierDismissible: false,
        builder: (context) => const Center(
          child: CircularProgressIndicator(),
        ),
      );

      // For demo purposes, we'll just show a success message
      await Future.delayed(const Duration(seconds: 1));
      
      if (context.mounted) {
        Navigator.of(context).pop(); // Close loading dialog
        
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(l10n.photoSaved),
            backgroundColor: Colors.green,
            action: SnackBarAction(
              label: 'Tamam',
              textColor: Colors.white,
              onPressed: () {},
            ),
          ),
        );
      }
    } catch (e) {
      if (context.mounted) {
        Navigator.of(context).pop(); // Close loading dialog
        
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Kaydetme hatası: ${e.toString()}'),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }

  Future<void> _shareImage(BuildContext context, String imageUrl) async {
    try {
      // For demo purposes, share app info
      await Share.share(
        'BabyMorph AI ile oluşturduğum bebek tahminini görün! 👶✨\n\nUygulama: BabyMorph AI',
        subject: 'BabyMorph AI - Bebek Tahmini',
      );
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Paylaşım hatası: ${e.toString()}'),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }
}