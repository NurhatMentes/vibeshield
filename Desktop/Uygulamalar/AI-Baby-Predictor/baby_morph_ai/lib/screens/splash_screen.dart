import 'package:flutter/material.dart';
import 'package:flutter_animate/flutter_animate.dart';
import 'package:provider/provider.dart';
import '../services/auth_service.dart';
import '../services/ad_service.dart';
import '../constants/app_theme.dart';
import 'home_screen.dart';
import '../flutter_gen/gen_l10n/app_localizations.dart';

class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key});

  @override
  State<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends State<SplashScreen> {
  @override
  void initState() {
    super.initState();
    _initializeApp();
  }

  Future<void> _initializeApp() async {
    // Servisleri başlat
    final authService = Provider.of<AuthService>(context, listen: false);
    final adService = Provider.of<AdService>(context, listen: false);

    // Anonymous giriş yap
    await authService.signInAnonymously();
    
    // Reklamları yükle
    adService.loadBannerAd();
    adService.loadInterstitialAd();

    // Splash screen süresini bekle
    await Future.delayed(const Duration(seconds: 3));

    if (mounted) {
      Navigator.of(context).pushReplacement(
        MaterialPageRoute(builder: (context) => const HomeScreen()),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    final l10n = AppLocalizations.of(context)!;
    
    return Scaffold(
      body: Container(
        decoration: const BoxDecoration(
          gradient: AppTheme.primaryGradient,
        ),
        child: SafeArea(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Spacer(flex: 2),
              
              // Logo
              Hero(
                tag: 'app_logo',
                child: Container(
                  width: 150,
                  height: 150,
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(30),
                    boxShadow: [
                      BoxShadow(
                        color: Colors.black.withOpacity(0.2),
                        blurRadius: 20,
                        offset: const Offset(0, 10),
                      ),
                    ],
                  ),
                  child: ClipRRect(
                    borderRadius: BorderRadius.circular(30),
                    child: Image.asset(
                      'assets/images/logo.png',
                      fit: BoxFit.cover,
                    ),
                  ),
                ),
              ).animate().scale(
                duration: 800.ms,
                curve: Curves.elasticOut,
              ),
              
              const SizedBox(height: 30),
              
              // App Title
              Text(
                l10n.appTitle,
                style: Theme.of(context).textTheme.displayMedium?.copyWith(
                  color: Colors.white,
                  fontWeight: FontWeight.bold,
                ),
              ).animate().fadeIn(
                duration: 600.ms,
                delay: 400.ms,
              ).slideY(
                begin: 0.3,
                end: 0,
                duration: 600.ms,
                delay: 400.ms,
                curve: Curves.easeOut,
              ),
              
              const SizedBox(height: 16),
              
              // Subtitle
              Text(
                l10n.splashSubtitle,
                style: Theme.of(context).textTheme.titleLarge?.copyWith(
                  color: Colors.white.withOpacity(0.9),
                  fontWeight: FontWeight.w500,
                ),
                textAlign: TextAlign.center,
              ).animate().fadeIn(
                duration: 600.ms,
                delay: 800.ms,
              ).slideY(
                begin: 0.3,
                end: 0,
                duration: 600.ms,
                delay: 800.ms,
                curve: Curves.easeOut,
              ),
              
              const Spacer(flex: 2),
              
              // Loading indicator
              Container(
                padding: const EdgeInsets.all(20),
                child: Column(
                  children: [
                    SizedBox(
                      width: 40,
                      height: 40,
                      child: CircularProgressIndicator(
                        valueColor: AlwaysStoppedAnimation<Color>(
                          Colors.white.withOpacity(0.8),
                        ),
                        strokeWidth: 3,
                      ),
                    ).animate().fadeIn(
                      duration: 600.ms,
                      delay: 1200.ms,
                    ),
                    
                    const SizedBox(height: 16),
                    
                    Text(
                      l10n.loading,
                      style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                        color: Colors.white.withOpacity(0.8),
                      ),
                    ).animate().fadeIn(
                      duration: 600.ms,
                      delay: 1400.ms,
                    ),
                  ],
                ),
              ),
              
              const Spacer(flex: 1),
              
              // Entertainment warning
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 40),
                child: Text(
                  l10n.forEntertainment,
                  style: Theme.of(context).textTheme.bodySmall?.copyWith(
                    color: Colors.white.withOpacity(0.7),
                    fontSize: 12,
                  ),
                  textAlign: TextAlign.center,
                ).animate().fadeIn(
                  duration: 600.ms,
                  delay: 1600.ms,
                ),
              ),
              
              const SizedBox(height: 20),
            ],
          ),
        ),
      ),
    );
  }
}