import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:provider/provider.dart';
import 'package:image_picker/image_picker.dart';
import 'package:google_mobile_ads/google_mobile_ads.dart';

import '../services/ai_service.dart';
import '../services/ad_service.dart';
import '../services/premium_service.dart';
import '../services/storage_service.dart';
import '../constants/app_theme.dart';
import '../widgets/photo_picker_card.dart';
import '../widgets/premium_banner.dart';
import 'result_screen.dart';
import 'privacy_policy_screen.dart';
import '../flutter_gen/gen_l10n/app_localizations.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  XFile? _motherPhoto;
  XFile? _fatherPhoto;
  String _selectedGender = 'boy'; // Varsayılan olarak erkek

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    
    return Scaffold(
      appBar: AppBar(
        title: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          mainAxisSize: MainAxisSize.min,
          children: [
            Container(
              width: 32,
              height: 32,
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(8),
              ),
              child: ClipRRect(
                borderRadius: BorderRadius.circular(8),
                child: Image.asset(
                  'assets/images/logo.png',
                  fit: BoxFit.cover,
                ),
              ),
            ),
            const SizedBox(width: 8),
            Text(l10n.appTitle),
          ],
        ),
        actions: [
          Consumer<PremiumService>(
            builder: (context, premiumService, child) {
              if (!premiumService.isPremium) {
                return IconButton(
                  icon: const Icon(Icons.star, color: AppTheme.primaryColor),
                  onPressed: () => _showPremiumDialog(context),
                );
              }
              return const SizedBox();
            },
          ),
          PopupMenuButton<String>(
            onSelected: (value) {
              if (value == 'privacy') {
                Navigator.of(context).push(
                  MaterialPageRoute(
                    builder: (context) => const PrivacyPolicyScreen(),
                  ),
                );
              }
            },
            itemBuilder: (context) => [
              PopupMenuItem(
                value: 'privacy',
                child: Row(
                  children: [
                    const Icon(Icons.privacy_tip),
                    const SizedBox(width: 8),
                    Text(l10n.privacyPolicy),
                  ],
                ),
              ),
            ],
          ),
        ],
      ),
      body: Column(
        children: [
          Expanded(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(20),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  // Welcome message
                  Container(
                    padding: const EdgeInsets.all(20),
                    decoration: BoxDecoration(
                      gradient: AppTheme.primaryGradient,
                      borderRadius: BorderRadius.circular(20),
                    ),
                    child: Column(
                      children: [
                        Text(
                          l10n.welcomeText,
                          style: Theme.of(context).textTheme.displaySmall?.copyWith(
                            color: Colors.white,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        const SizedBox(height: 8),
                        Text(
                          l10n.splashSubtitle,
                          style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                            color: Colors.white.withOpacity(0.9),
                          ),
                          textAlign: TextAlign.center,
                        ),
                      ],
                    ),
                  ).animate().fadeIn(duration: 600.ms).slideY(
                    begin: -0.2,
                    end: 0,
                    duration: 600.ms,
                    curve: Curves.easeOut,
                  ),
                  
                  const SizedBox(height: 30),
                  
                  // Photo selection cards
                  Row(
                    children: [
                      Expanded(
                        child: PhotoPickerCard(
                          title: l10n.motherPhoto,
                          selectedPhoto: _motherPhoto,
                          onPhotoSelected: (photo) {
                            setState(() {
                              _motherPhoto = photo;
                            });
                          },
                          icon: Icons.woman,
                          color: Colors.pink.shade300,
                        ).animate().fadeIn(
                          duration: 600.ms,
                          delay: 200.ms,
                        ).slideX(
                          begin: -0.3,
                          end: 0,
                          duration: 600.ms,
                          delay: 200.ms,
                          curve: Curves.easeOut,
                        ),
                      ),
                      const SizedBox(width: 16),
                      Expanded(
                        child: PhotoPickerCard(
                          title: l10n.fatherPhoto,
                          selectedPhoto: _fatherPhoto,
                          onPhotoSelected: (photo) {
                            setState(() {
                              _fatherPhoto = photo;
                            });
                          },
                          icon: Icons.man,
                          color: Colors.blue.shade300,
                        ).animate().fadeIn(
                          duration: 600.ms,
                          delay: 400.ms,
                        ).slideX(
                          begin: 0.3,
                          end: 0,
                          duration: 600.ms,
                          delay: 400.ms,
                          curve: Curves.easeOut,
                        ),
                      ),
                    ],
                  ),
                  
                  const SizedBox(height: 30),
                  
                  // Gender selection
                  Container(
                    padding: const EdgeInsets.all(20),
                    decoration: BoxDecoration(
                      color: Colors.white,
                      borderRadius: BorderRadius.circular(16),
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withOpacity(0.1),
                          blurRadius: 10,
                          offset: const Offset(0, 5),
                        ),
                      ],
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'Bebek Cinsiyeti',
                          style: Theme.of(context).textTheme.titleMedium?.copyWith(
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        const SizedBox(height: 16),
                        Row(
                          children: [
                            Expanded(
                              child: GestureDetector(
                                onTap: () {
                                  setState(() {
                                    _selectedGender = 'boy';
                                  });
                                },
                                child: Container(
                                  padding: const EdgeInsets.symmetric(vertical: 12),
                                  decoration: BoxDecoration(
                                    color: _selectedGender == 'boy' 
                                        ? Colors.blue.shade100 
                                        : Colors.grey.shade100,
                                    borderRadius: BorderRadius.circular(12),
                                    border: Border.all(
                                      color: _selectedGender == 'boy' 
                                          ? Colors.blue 
                                          : Colors.grey.shade300,
                                      width: 2,
                                    ),
                                  ),
                                  child: Row(
                                    mainAxisAlignment: MainAxisAlignment.center,
                                    children: [
                                      Icon(
                                        Icons.boy,
                                        color: _selectedGender == 'boy' 
                                            ? Colors.blue 
                                            : Colors.grey.shade600,
                                      ),
                                      const SizedBox(width: 8),
                                      Text(
                                        'Erkek',
                                        style: TextStyle(
                                          color: _selectedGender == 'boy' 
                                              ? Colors.blue 
                                              : Colors.grey.shade600,
                                          fontWeight: FontWeight.w600,
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                              ),
                            ),
                            const SizedBox(width: 12),
                            Expanded(
                              child: GestureDetector(
                                onTap: () {
                                  setState(() {
                                    _selectedGender = 'girl';
                                  });
                                },
                                child: Container(
                                  padding: const EdgeInsets.symmetric(vertical: 12),
                                  decoration: BoxDecoration(
                                    color: _selectedGender == 'girl' 
                                        ? Colors.pink.shade100 
                                        : Colors.grey.shade100,
                                    borderRadius: BorderRadius.circular(12),
                                    border: Border.all(
                                      color: _selectedGender == 'girl' 
                                          ? Colors.pink 
                                          : Colors.grey.shade300,
                                      width: 2,
                                    ),
                                  ),
                                  child: Row(
                                    mainAxisAlignment: MainAxisAlignment.center,
                                    children: [
                                      Icon(
                                        Icons.girl,
                                        color: _selectedGender == 'girl' 
                                            ? Colors.pink 
                                            : Colors.grey.shade600,
                                      ),
                                      const SizedBox(width: 8),
                                      Text(
                                        'Kız',
                                        style: TextStyle(
                                          color: _selectedGender == 'girl' 
                                              ? Colors.pink 
                                              : Colors.grey.shade600,
                                          fontWeight: FontWeight.w600,
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ).animate().fadeIn(
                    duration: 600.ms,
                    delay: 600.ms,
                  ).slideY(
                    begin: 0.3,
                    end: 0,
                    duration: 600.ms,
                    delay: 600.ms,
                    curve: Curves.easeOut,
                  ),
                  
                  const SizedBox(height: 30),
                  
                  // Generate baby button
                  Consumer2<AIService, PremiumService>(
                    builder: (context, aiService, premiumService, child) {
                      final bool canGenerate = _motherPhoto != null && _fatherPhoto != null;
                      
                      return ElevatedButton(
                        onPressed: canGenerate && !aiService.isProcessing
                            ? () => _generateBabyPhoto(context)
                            : null,
                        style: ElevatedButton.styleFrom(
                          padding: const EdgeInsets.symmetric(vertical: 16),
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(16),
                          ),
                        ),
                        child: aiService.isProcessing
                            ? Row(
                                mainAxisAlignment: MainAxisAlignment.center,
                                children: [
                                  const SizedBox(
                                    width: 20,
                                    height: 20,
                                    child: CircularProgressIndicator(
                                      strokeWidth: 2,
                                      valueColor: AlwaysStoppedAnimation<Color>(Colors.white),
                                    ),
                                  ),
                                  const SizedBox(width: 12),
                                  Text(l10n.processing),
                                ],
                              )
                            : Row(
                                mainAxisAlignment: MainAxisAlignment.center,
                                children: [
                                  const Icon(Icons.auto_awesome),
                                  const SizedBox(width: 8),
                                  Text(
                                    l10n.seeTheBaby,
                                    style: const TextStyle(
                                      fontSize: 18,
                                      fontWeight: FontWeight.w600,
                                    ),
                                  ),
                                ],
                              ),
                      );
                    },
                  ).animate().fadeIn(
                    duration: 600.ms,
                    delay: 600.ms,
                  ).slideY(
                    begin: 0.3,
                    end: 0,
                    duration: 600.ms,
                    delay: 600.ms,
                    curve: Curves.easeOut,
                  ),
                  
                  const SizedBox(height: 20),
                  
                  // Premium banner (if not premium)
                  Consumer<PremiumService>(
                    builder: (context, premiumService, child) {
                      if (!premiumService.isPremium) {
                        return const PremiumBanner().animate().fadeIn(
                          duration: 600.ms,
                          delay: 800.ms,
                        );
                      }
                      return const SizedBox();
                    },
                  ),
                  
                  const SizedBox(height: 20),
                  
                  // Entertainment disclaimer
                  Container(
                    padding: const EdgeInsets.all(16),
                    decoration: BoxDecoration(
                      color: Colors.orange.shade50,
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(
                        color: Colors.orange.shade200,
                      ),
                    ),
                    child: Row(
                      children: [
                        Icon(
                          Icons.info_outline,
                          color: Colors.orange.shade700,
                          size: 20,
                        ),
                        const SizedBox(width: 12),
                        Expanded(
                          child: Text(
                            l10n.forEntertainment,
                            style: TextStyle(
                              color: Colors.orange.shade700,
                              fontSize: 12,
                              fontWeight: FontWeight.w500,
                            ),
                          ),
                        ),
                      ],
                    ),
                  ).animate().fadeIn(
                    duration: 600.ms,
                    delay: 1000.ms,
                  ),
                ],
              ),
            ),
          ),
          
          // Banner Ad
          Consumer2<AdService, PremiumService>(
            builder: (context, adService, premiumService, child) {
              if (!premiumService.isPremium && adService.isBannerAdLoaded && adService.bannerAd != null) {
                return Container(
                  alignment: Alignment.center,
                  width: adService.bannerAd!.size.width.toDouble(),
                  height: adService.bannerAd!.size.height.toDouble(),
                  child: AdWidget(ad: adService.bannerAd!),
                );
              }
              return const SizedBox();
            },
          ),
        ],
      ),
    );
  }

  Future<void> _generateBabyPhoto(BuildContext context) async {
    if (_motherPhoto == null || _fatherPhoto == null) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(AppLocalizations.of(context)!.selectBothPhotos),
          backgroundColor: Colors.red,
        ),
      );
      return;
    }

    final aiService = Provider.of<AIService>(context, listen: false);
    final adService = Provider.of<AdService>(context, listen: false);
    final premiumService = Provider.of<PremiumService>(context, listen: false);
    final storageService = Provider.of<StorageService>(context, listen: false);

    try {
      // AI ile bebek fotoğrafı oluştur (local path'leri kullan)
      final bool success = await aiService.generateBabyPhoto(
        motherImagePath: _motherPhoto!.path,
        fatherImagePath: _fatherPhoto!.path,
        gender: _selectedGender,
      );

      if (success) {
        // Interstitial reklam göster (premium değilse)
        if (!premiumService.isPremium && adService.isInterstitialAdLoaded) {
          adService.showInterstitialAd();
        }

        // Sonuç ekranına git
        if (mounted) {
          Navigator.of(context).push(
            MaterialPageRoute(
              builder: (context) => const ResultScreen(),
            ),
          );
        }
      } else {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(aiService.error ?? AppLocalizations.of(context)!.errorOccurred),
              backgroundColor: Colors.red,
            ),
          );
        }
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).hideCurrentSnackBar();
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Hata: ${e.toString()}'),
            backgroundColor: Colors.red,
          ),
        );
      }
    }
  }

  void _showPremiumDialog(BuildContext context) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(AppLocalizations.of(context)!.premiumFeatures),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(AppLocalizations.of(context)!.premiumDescription),
            const SizedBox(height: 16),
            Text(
              AppLocalizations.of(context)!.premiumPrice,
              style: const TextStyle(
                fontSize: 24,
                fontWeight: FontWeight.bold,
                color: AppTheme.primaryColor,
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('İptal'),
          ),
          ElevatedButton(
            onPressed: () {
              Navigator.of(context).pop();
              _purchasePremium(context);
            },
            child: Text(AppLocalizations.of(context)!.subscribe),
          ),
        ],
      ),
    );
  }

  Future<void> _purchasePremium(BuildContext context) async {
    final premiumService = Provider.of<PremiumService>(context, listen: false);
    final success = await premiumService.purchasePremium();
    
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(success ? 'Premium satın alındı!' : 'Satın alma başarısız'),
          backgroundColor: success ? Colors.green : Colors.red,
        ),
      );
    }
  }
}