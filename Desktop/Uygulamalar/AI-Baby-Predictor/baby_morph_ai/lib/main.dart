import 'package:flutter/material.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:firebase_core/firebase_core.dart';
import 'package:provider/provider.dart';
import 'package:google_mobile_ads/google_mobile_ads.dart';
import 'package:flutter_dotenv/flutter_dotenv.dart';

import 'firebase_options.dart';
import 'screens/splash_screen.dart';
import 'services/ad_service.dart';
import 'services/auth_service.dart';
import 'services/storage_service.dart';
import 'services/ai_service.dart';
import 'services/premium_service.dart';
import 'constants/app_theme.dart';
import 'flutter_gen/gen_l10n/app_localizations.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  // Environment variables yükleme
  await dotenv.load(fileName: ".env");
  
  // Firebase başlatma
  await Firebase.initializeApp(
    options: DefaultFirebaseOptions.currentPlatform,
  );
  
  // AdMob başlatma
  MobileAds.instance.initialize();
  
  runApp(const BabyMorphApp());
}

class BabyMorphApp extends StatelessWidget {
  const BabyMorphApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        ChangeNotifierProvider(create: (_) => AuthService()),
        ChangeNotifierProvider(create: (_) => StorageService()),
        ChangeNotifierProvider(create: (_) => AIService()),
        ChangeNotifierProvider(create: (_) => PremiumService()),
        ChangeNotifierProvider(create: (_) => AdService()),
      ],
      child: MaterialApp(
        title: 'BabyMorph AI',
        debugShowCheckedModeBanner: false,
        theme: AppTheme.lightTheme,
        darkTheme: AppTheme.darkTheme,
        themeMode: ThemeMode.system,
        localizationsDelegates: const [
          AppLocalizations.delegate,
          GlobalMaterialLocalizations.delegate,
          GlobalWidgetsLocalizations.delegate,
          GlobalCupertinoLocalizations.delegate,
        ],
        supportedLocales: const [
          Locale('tr', ''), // Türkçe
          Locale('en', ''), // İngilizce
        ],
        locale: const Locale('tr', ''), // Varsayılan Türkçe
        home: const SplashScreen(),
      ),
    );
  }
}
