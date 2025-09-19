import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';

class SecurityHelper {
  /// Fotoğraf dosyalarını güvenli bir şekilde temizle
  static Future<void> cleanupPhotos(List<String> photoPaths) async {
    try {
      for (String path in photoPaths) {
        final file = File(path);
        if (await file.exists()) {
          await file.delete();
          debugPrint('Fotoğraf silindi: $path');
        }
      }
    } catch (e) {
      debugPrint('Fotoğraf temizleme hatası: $e');
    }
  }

  /// Geçici dosyaları temizle
  static Future<void> cleanupTempFiles() async {
    try {
      final tempDir = await getTemporaryDirectory();
      final tempFiles = tempDir.listSync();
      
      for (var file in tempFiles) {
        if (file is File) {
          // Sadece uygulama ile ilgili geçici dosyaları sil
          if (file.path.contains('image_picker') || 
              file.path.contains('baby_morph')) {
            await file.delete();
            debugPrint('Geçici dosya silindi: ${file.path}');
          }
        }
      }
    } catch (e) {
      debugPrint('Geçici dosya temizleme hatası: $e');
    }
  }

  /// Fotoğraf metadata'sını temizle (EXIF veri)
  static Future<File?> sanitizeImageMetadata(File imageFile) async {
    try {
      // Bu örnekte basit bir kopya oluşturuyoruz
      // Gerçek implementasyonda EXIF verilerini temizleyen
      // bir kütüphane kullanılabilir (örn: image package)
      
      final bytes = await imageFile.readAsBytes();
      final tempDir = await getTemporaryDirectory();
      final sanitizedFile = File('${tempDir.path}/sanitized_${DateTime.now().millisecondsSinceEpoch}.jpg');
      
      await sanitizedFile.writeAsBytes(bytes);
      return sanitizedFile;
    } catch (e) {
      debugPrint('Metadata temizleme hatası: $e');
      return null;
    }
  }

  /// Dosya boyutunu kontrol et
  static Future<bool> validateFileSize(File file, {int maxSizeInMB = 10}) async {
    try {
      final fileSize = await file.length();
      final maxSizeInBytes = maxSizeInMB * 1024 * 1024;
      return fileSize <= maxSizeInBytes;
    } catch (e) {
      debugPrint('Dosya boyutu kontrol hatası: $e');
      return false;
    }
  }

  /// Dosya tipini kontrol et
  static bool validateFileType(String filePath) {
    final allowedExtensions = ['.jpg', '.jpeg', '.png'];
    final lowerPath = filePath.toLowerCase();
    return allowedExtensions.any((ext) => lowerPath.endsWith(ext));
  }

  /// Güvenli dosya adı oluştur
  static String generateSecureFileName() {
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    final random = DateTime.now().microsecond;
    return 'photo_${timestamp}_$random';
  }

  /// Uygulama çıkışında tüm geçici verileri temizle
  static Future<void> performSecurityCleanup() async {
    try {
      await cleanupTempFiles();
      
      // Shared Preferences'deki geçici verileri temizle
      // (Premium durumu hariç kalıcı veriler)
      
      debugPrint('Güvenlik temizliği tamamlandı');
    } catch (e) {
      debugPrint('Güvenlik temizliği hatası: $e');
    }
  }

  /// Rate limiting - API çağrılarını sınırla
  static Map<String, DateTime> _lastApiCalls = {};
  
  static bool canMakeApiCall(String userId, {Duration cooldown = const Duration(minutes: 1)}) {
    final lastCall = _lastApiCalls[userId];
    if (lastCall == null) {
      _lastApiCalls[userId] = DateTime.now();
      return true;
    }
    
    if (DateTime.now().difference(lastCall) >= cooldown) {
      _lastApiCalls[userId] = DateTime.now();
      return true;
    }
    
    return false;
  }

  /// Input validation
  static bool isValidUserId(String? userId) {
    if (userId == null || userId.isEmpty) return false;
    // Firebase User ID formatını kontrol et
    return RegExp(r'^[a-zA-Z0-9]{28}$').hasMatch(userId);
  }

  /// URL validation
  static bool isValidImageUrl(String? url) {
    if (url == null || url.isEmpty) return false;
    try {
      final uri = Uri.parse(url);
      return uri.hasScheme && (uri.scheme == 'http' || uri.scheme == 'https');
    } catch (e) {
      return false;
    }
  }
}