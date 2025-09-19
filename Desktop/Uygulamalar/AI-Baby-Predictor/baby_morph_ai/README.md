# BabyMorph AI

AI-powered baby prediction mobile app built with Flutter. Upload photos of parents and get a fun prediction of how their baby might look like!

## Features

✨ **Core Features:**
- AI baby prediction from parent photos
- Turkish and English language support
- Modern, user-friendly interface
- Photo selection from camera or gallery

🚀 **Premium Features:**
- High-resolution results
- Ad-free experience
- Unlimited predictions

📱 **Technical Features:**
- Firebase Authentication (Anonymous)
- Firebase Storage for photos
- AdMob integration
- In-app purchase system
- Privacy-focused (photos auto-deleted after processing)

## Setup Instructions

### Prerequisites

1. Flutter SDK (>=3.8.1)
2. Firebase project
3. Android Studio / Xcode
4. Google AdMob account
5. Hugging Face API key (optional)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/baby-morph-ai.git
   cd baby-morph-ai
   ```

2. **Install dependencies:**
   ```bash
   flutter pub get
   ```

3. **Firebase Setup:**
   - Create a new Firebase project at [Firebase Console](https://console.firebase.google.com/)
   - Enable Authentication (Anonymous)
   - Enable Firestore
   - Enable Storage
   - Download `google-services.json` for Android
   - Download `GoogleService-Info.plist` for iOS
   - Replace the demo files in `/android/app/` and `/ios/Runner/`
   - Update `firebase_options.dart` with your actual Firebase configuration

4. **AdMob Setup:**
   - Create AdMob account and get App IDs
   - Update Ad Unit IDs in `services/ad_service.dart`
   - Add AdMob App ID to platform-specific configs

5. **Hugging Face API (Optional):**
   - Get API key from [Hugging Face](https://huggingface.co/)
   - Update `services/ai_service.dart` with your API key
   - Or use the demo simulation mode

### Running the App

```bash
# Debug mode
flutter run

# Release mode
flutter run --release

# Build APK
flutter build apk --release

# Build iOS
flutter build ios --release
```

## Project Structure

```
lib/
├── constants/
│   └── app_theme.dart          # App theme and styles
├── flutter_gen/
│   └── gen_l10n/              # Generated localization files
├── l10n/
│   └── arb/                   # Translation files
├── screens/
│   ├── splash_screen.dart     # App splash screen
│   ├── home_screen.dart       # Main photo upload screen
│   ├── result_screen.dart     # AI result display
│   └── privacy_policy_screen.dart
├── services/
│   ├── auth_service.dart      # Firebase Authentication
│   ├── storage_service.dart   # Firebase Storage
│   ├── ai_service.dart        # AI processing
│   ├── ad_service.dart        # AdMob integration
│   └── premium_service.dart   # In-app purchases
├── utils/
│   └── security_helper.dart   # Security utilities
├── widgets/
│   ├── photo_picker_card.dart
│   └── premium_banner.dart
├── firebase_options.dart       # Firebase configuration
└── main.dart                  # App entry point
```

## Configuration Files

### Firebase
- `android/app/google-services.json`
- `ios/Runner/GoogleService-Info.plist`
- `lib/firebase_options.dart`

### Localization
- `l10n.yaml`
- `lib/l10n/arb/app_tr.arb` (Turkish)
- `lib/l10n/arb/app_en.arb` (English)

## Privacy & Security

- Photos are automatically deleted after AI processing
- Anonymous authentication only
- No personal data collection
- GDPR compliant
- Entertainment purposes only disclaimer

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

⚠️ **For Entertainment Purposes Only**

This app is designed purely for entertainment and fun. The AI predictions are not scientifically accurate and should not be taken seriously. Results may vary and are not guaranteed to represent actual genetic outcomes.

## Support

For support and questions:
- Email: support@babymorph.ai
- Website: www.babymorph.ai

---

🎉 **Have fun creating baby predictions!** 👶✨
