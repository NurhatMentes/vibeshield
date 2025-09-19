// This is a basic Flutter widget test.
//
// To perform an interaction with a widget in your test, use the WidgetTester
// utility in the flutter_test package. For example, you can send tap and scroll
// gestures. You can also use WidgetTester to find child widgets in the widget
// tree, read text, and verify that the values of widget properties are correct.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:baby_morph_ai/constants/app_theme.dart';
import 'package:baby_morph_ai/services/ai_service.dart';
import 'package:baby_morph_ai/services/premium_service.dart';

void main() {
  testWidgets('App Theme test', (WidgetTester tester) async {
    // Test that app theme loads correctly
    expect(AppTheme.primaryColor, const Color(0xFFFF6B47));
    expect(AppTheme.lightTheme.primaryColor, AppTheme.primaryColor);
  });

  test('AI Service test', () {
    final aiService = AIService();
    expect(aiService.isProcessing, false);
    expect(aiService.resultImageUrl, null);
    expect(aiService.error, null);
  });

  test('Premium Service test', () {
    final premiumService = PremiumService();
    expect(premiumService.isPremium, false);
    expect(premiumService.isLoading, false);
  });

  testWidgets('Simple widget test', (WidgetTester tester) async {
    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: const Center(
            child: Text('BabyMorph AI Test'),
          ),
        ),
      ),
    );

    expect(find.text('BabyMorph AI Test'), findsOneWidget);
  });
}
