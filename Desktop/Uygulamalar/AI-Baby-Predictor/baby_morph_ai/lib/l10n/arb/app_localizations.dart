import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/widgets.dart';
import 'package:flutter_localizations/flutter_localizations.dart';
import 'package:intl/intl.dart' as intl;

import 'app_localizations_en.dart';
import 'app_localizations_tr.dart';

// ignore_for_file: type=lint

/// Callers can lookup localized strings with an instance of AppLocalizations
/// returned by `AppLocalizations.of(context)`.
///
/// Applications need to include `AppLocalizations.delegate()` in their app's
/// `localizationDelegates` list, and the locales they support in the app's
/// `supportedLocales` list. For example:
///
/// ```dart
/// import 'arb/app_localizations.dart';
///
/// return MaterialApp(
///   localizationsDelegates: AppLocalizations.localizationsDelegates,
///   supportedLocales: AppLocalizations.supportedLocales,
///   home: MyApplicationHome(),
/// );
/// ```
///
/// ## Update pubspec.yaml
///
/// Please make sure to update your pubspec.yaml to include the following
/// packages:
///
/// ```yaml
/// dependencies:
///   # Internationalization support.
///   flutter_localizations:
///     sdk: flutter
///   intl: any # Use the pinned version from flutter_localizations
///
///   # Rest of dependencies
/// ```
///
/// ## iOS Applications
///
/// iOS applications define key application metadata, including supported
/// locales, in an Info.plist file that is built into the application bundle.
/// To configure the locales supported by your app, you’ll need to edit this
/// file.
///
/// First, open your project’s ios/Runner.xcworkspace Xcode workspace file.
/// Then, in the Project Navigator, open the Info.plist file under the Runner
/// project’s Runner folder.
///
/// Next, select the Information Property List item, select Add Item from the
/// Editor menu, then select Localizations from the pop-up menu.
///
/// Select and expand the newly-created Localizations item then, for each
/// locale your application supports, add a new item and select the locale
/// you wish to add from the pop-up menu in the Value field. This list should
/// be consistent with the languages listed in the AppLocalizations.supportedLocales
/// property.
abstract class AppLocalizations {
  AppLocalizations(String locale)
    : localeName = intl.Intl.canonicalizedLocale(locale.toString());

  final String localeName;

  static AppLocalizations? of(BuildContext context) {
    return Localizations.of<AppLocalizations>(context, AppLocalizations);
  }

  static const LocalizationsDelegate<AppLocalizations> delegate =
      _AppLocalizationsDelegate();

  /// A list of this localizations delegate along with the default localizations
  /// delegates.
  ///
  /// Returns a list of localizations delegates containing this delegate along with
  /// GlobalMaterialLocalizations.delegate, GlobalCupertinoLocalizations.delegate,
  /// and GlobalWidgetsLocalizations.delegate.
  ///
  /// Additional delegates can be added by appending to this list in
  /// MaterialApp. This list does not have to be used at all if a custom list
  /// of delegates is preferred or required.
  static const List<LocalizationsDelegate<dynamic>> localizationsDelegates =
      <LocalizationsDelegate<dynamic>>[
        delegate,
        GlobalMaterialLocalizations.delegate,
        GlobalCupertinoLocalizations.delegate,
        GlobalWidgetsLocalizations.delegate,
      ];

  /// A list of this localizations delegate's supported locales.
  static const List<Locale> supportedLocales = <Locale>[
    Locale('en'),
    Locale('tr'),
  ];

  /// Uygulama başlığı
  ///
  /// In tr, this message translates to:
  /// **'BabyMorph AI'**
  String get appTitle;

  /// Açılış ekranı alt başlığı
  ///
  /// In tr, this message translates to:
  /// **'AI Baby Predictor – Just for Fun!'**
  String get splashSubtitle;

  /// Hoş geldin mesajı
  ///
  /// In tr, this message translates to:
  /// **'Hoş Geldiniz!'**
  String get welcomeText;

  /// Anne fotoğrafı butonu
  ///
  /// In tr, this message translates to:
  /// **'Anne Fotoğrafı'**
  String get motherPhoto;

  /// Baba fotoğrafı butonu
  ///
  /// In tr, this message translates to:
  /// **'Baba Fotoğrafı'**
  String get fatherPhoto;

  /// Bebek görme butonu
  ///
  /// In tr, this message translates to:
  /// **'Bebeği Gör'**
  String get seeTheBaby;

  /// Fotoğraf seçme mesajı
  ///
  /// In tr, this message translates to:
  /// **'Fotoğraf Seç'**
  String get selectPhoto;

  /// İşlem devam ediyor mesajı
  ///
  /// In tr, this message translates to:
  /// **'İşleniyor...'**
  String get processing;

  /// Kaydet butonu
  ///
  /// In tr, this message translates to:
  /// **'Kaydet'**
  String get save;

  /// Paylaş butonu
  ///
  /// In tr, this message translates to:
  /// **'Paylaş'**
  String get share;

  /// Premium buton
  ///
  /// In tr, this message translates to:
  /// **'Premium'**
  String get premium;

  /// Premium özellikler başlığı
  ///
  /// In tr, this message translates to:
  /// **'Premium Özellikler'**
  String get premiumFeatures;

  /// Premium açıklaması
  ///
  /// In tr, this message translates to:
  /// **'Sınırsız yüksek çözünürlük ve reklamsız kullanım'**
  String get premiumDescription;

  /// Premium fiyatı
  ///
  /// In tr, this message translates to:
  /// **'299,90 ₺'**
  String get premiumPrice;

  /// Abone ol butonu
  ///
  /// In tr, this message translates to:
  /// **'Abone Ol'**
  String get subscribe;

  /// Eğlence amaçlı uyarısı
  ///
  /// In tr, this message translates to:
  /// **'Yalnızca eğlence amaçlıdır'**
  String get forEntertainment;

  /// Gizlilik politikası
  ///
  /// In tr, this message translates to:
  /// **'Gizlilik Politikası'**
  String get privacyPolicy;

  /// Hata mesajı
  ///
  /// In tr, this message translates to:
  /// **'Hata'**
  String get error;

  /// Genel hata mesajı
  ///
  /// In tr, this message translates to:
  /// **'Bir hata oluştu'**
  String get errorOccurred;

  /// İki fotoğraf seçilmediğinde uyarı
  ///
  /// In tr, this message translates to:
  /// **'Lütfen her iki fotoğrafı da seçiniz'**
  String get selectBothPhotos;

  /// Fotoğraf kaydetme başarılı mesajı
  ///
  /// In tr, this message translates to:
  /// **'Fotoğraf kaydedildi'**
  String get photoSaved;

  /// Yükleme mesajı
  ///
  /// In tr, this message translates to:
  /// **'Yükleniyor...'**
  String get loading;
}

class _AppLocalizationsDelegate
    extends LocalizationsDelegate<AppLocalizations> {
  const _AppLocalizationsDelegate();

  @override
  Future<AppLocalizations> load(Locale locale) {
    return SynchronousFuture<AppLocalizations>(lookupAppLocalizations(locale));
  }

  @override
  bool isSupported(Locale locale) =>
      <String>['en', 'tr'].contains(locale.languageCode);

  @override
  bool shouldReload(_AppLocalizationsDelegate old) => false;
}

AppLocalizations lookupAppLocalizations(Locale locale) {
  // Lookup logic when only language code is specified.
  switch (locale.languageCode) {
    case 'en':
      return AppLocalizationsEn();
    case 'tr':
      return AppLocalizationsTr();
  }

  throw FlutterError(
    'AppLocalizations.delegate failed to load unsupported locale "$locale". This is likely '
    'an issue with the localizations generation tool. Please file an issue '
    'on GitHub with a reproducible sample app and the gen-l10n configuration '
    'that was used.',
  );
}
