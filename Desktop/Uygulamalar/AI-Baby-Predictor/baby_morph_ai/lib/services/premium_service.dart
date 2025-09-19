import 'package:flutter/foundation.dart';
import 'package:in_app_purchase/in_app_purchase.dart';
import 'package:shared_preferences/shared_preferences.dart';

class PremiumService extends ChangeNotifier {
  bool _isPremium = false;
  bool _isLoading = false;
  String? _error;

  bool get isPremium => _isPremium;
  bool get isLoading => _isLoading;
  String? get error => _error;

  static const String _premiumProductId = 'baby_morph_premium';
  static const String _premiumKey = 'is_premium_user';

  PremiumService() {
    _loadPremiumStatus();
  }

  Future<void> _loadPremiumStatus() async {
    final prefs = await SharedPreferences.getInstance();
    _isPremium = prefs.getBool(_premiumKey) ?? false;
    notifyListeners();
  }

  Future<bool> purchasePremium() async {
    try {
      _isLoading = true;
      _error = null;
      notifyListeners();

      final bool available = await InAppPurchase.instance.isAvailable();
      if (!available) {
        _error = 'Satın alma mevcut değil';
        _isLoading = false;
        notifyListeners();
        return false;
      }

      // Demo için simüle edilmiş satın alma
      await Future.delayed(const Duration(seconds: 2));
      
      await _setPremiumStatus(true);
      
      _isLoading = false;
      notifyListeners();
      return true;
    } catch (e) {
      _error = 'Satın alma hatası: ${e.toString()}';
      _isLoading = false;
      notifyListeners();
      return false;
    }
  }

  Future<void> _setPremiumStatus(bool isPremium) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_premiumKey, isPremium);
    _isPremium = isPremium;
    notifyListeners();
  }

  Future<void> restorePurchases() async {
    try {
      _isLoading = true;
      notifyListeners();

      // Gerçek implementasyon için restore logic
      await Future.delayed(const Duration(seconds: 1));
      
      _isLoading = false;
      notifyListeners();
    } catch (e) {
      _error = 'Geri yükleme hatası: ${e.toString()}';
      _isLoading = false;
      notifyListeners();
    }
  }

  void clearError() {
    _error = null;
    notifyListeners();
  }
}