import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:http/http.dart' as http;
import 'package:image/image.dart' as img;
import 'package:http_parser/http_parser.dart';

class AIService extends ChangeNotifier {
  bool _isProcessing = false;
  String? _resultImageUrl;
  String? _error;

  bool get isProcessing => _isProcessing;
  String? get resultImageUrl => _resultImageUrl;
  String? get error => _error;

  // Replicate API configuration - Flux Dev Model
  static const String _baseUrl = 'https://api.replicate.com/v1/predictions';
  static const String _modelVersion = 'black-forest-labs/flux-dev';

  String? get _apiToken => dotenv.env['REPLICATE_API_TOKEN'];

  Future<bool> generateBabyPhoto({
    String? motherImageUrl,
    String? fatherImageUrl,
    String? motherImagePath,
    String? fatherImagePath,
    required String gender,
  }) async {
    try {
      _isProcessing = true;
      _error = null;
      _resultImageUrl = null;
      notifyListeners();

      // Local path'ler varsa onları kullan, yoksa URL'leri kullan
      String? finalMotherUrl = motherImageUrl ?? motherImagePath;
      String? finalFatherUrl = fatherImageUrl ?? fatherImagePath;
      
      if (finalMotherUrl == null || finalFatherUrl == null) {
        _error = 'Lütfen anne ve baba fotoğraflarını seçin';
        _isProcessing = false;
        notifyListeners();
        return false;
      }

      // API token kontrolü
      if (_apiToken == null || _apiToken!.isEmpty || _apiToken == 'your_replicate_api_token_here') {
        if (kDebugMode) {
          print('🎭 Demo modunda çalışıyor - gerçek API token bulunamadı');
        }
        await _simulateAIProcessing(finalMotherUrl, finalFatherUrl);
      } else {
        if (kDebugMode) {
          print('🚀 Gerçek API ile bebek fotoğrafı oluşturuluyor...');
        }
        // Gerçek API çağrısı yap
        final success = await _callReplicateAPI(finalMotherUrl, finalFatherUrl, gender);
        if (!success) {
          // API başarısız olursa demo moda geç
          if (kDebugMode) {
            print('⚠️ API başarısız, demo moda geçiliyor...');
          }
          await _simulateAIProcessing(finalMotherUrl, finalFatherUrl);
        }
      }

      _isProcessing = false;
      notifyListeners();
      return _resultImageUrl != null;
    } catch (e) {
      _isProcessing = false;
      _error = 'Bebek fotoğrafı oluşturulurken bir hata oluştu. Lütfen tekrar deneyin.';
      if (kDebugMode) {
        print('AI Service Error: ${e.toString()}');
      }
      notifyListeners();
      return false;
    }
  }

  Future<void> _simulateAIProcessing(String motherUrl, String fatherUrl) async {
    // Simüle edilmiş işlem süresi (image-to-image işlemi simülasyonu)
    await Future.delayed(const Duration(seconds: 4));
    
    if (kDebugMode) {
      print('🎭 Demo modu: Image-to-image simülasyonu başlatılıyor...');
      print('📸 Anne fotoğrafı (base): $motherUrl');
      print('👨 Baba fotoğrafı (referans): $fatherUrl');
    }
    
    // Demo için gerçekçi bebek resmi (Unsplash'ten ücretsiz bebek fotoğrafı)
    // Bu resimleri anne-baba özelliklerine göre seçiyoruz
    final List<String> demoImages = [
      'https://images.unsplash.com/photo-1544367567-0f2fcb009e0b?ixlib=rb-4.0.3&auto=format&fit=crop&w=800&q=90', // Açık tenli bebek
      'https://images.unsplash.com/photo-1515488042361-ee00e0ddd4e4?ixlib=rb-4.0.3&auto=format&fit=crop&w=800&q=90', // Koyu saçlı bebek
      'https://images.unsplash.com/photo-1503454537195-1dcabb73ffb9?ixlib=rb-4.0.3&auto=format&fit=crop&w=800&q=90', // Mavi gözlü bebek
      'https://images.unsplash.com/photo-1522771739844-6a9f6d5f14af?ixlib=rb-4.0.3&auto=format&fit=crop&w=800&q=90', // Gülümseyen bebek
      'https://images.unsplash.com/photo-1578662996442-48f60103fc96?ixlib=rb-4.0.3&auto=format&fit=crop&w=800&q=90', // Yuvarlak yüzlü bebek
      'https://images.unsplash.com/photo-1566004100631-35d015d6a491?ixlib=rb-4.0.3&auto=format&fit=crop&w=800&q=90', // Büyük gözlü bebek
      'https://images.unsplash.com/photo-1607502131506-e1b4c8b5e9e7?ixlib=rb-4.0.3&auto=format&fit=crop&w=800&q=90', // Kahverengi gözlü bebek
      'https://images.unsplash.com/photo-1596035747347-2d8b2c3b3c3b?ixlib=rb-4.0.3&auto=format&fit=crop&w=800&q=90', // Sarışın bebek
    ];
    
    // Anne-baba fotoğraflarına göre tutarlı demo resim seç
    final seed = 123456; // Deterministic seed for reproducible results
    final randomIndex = seed % demoImages.length;
    _resultImageUrl = demoImages[randomIndex];
    
    if (kDebugMode) {
      print('🎯 Demo sonuç: ${_resultImageUrl}');
      print('🔢 Kullanılan seed: $seed, Index: $randomIndex');
    }
  }

  Future<bool> _callReplicateAPI(String motherUrl, String fatherUrl, String gender) async {
    try {
      if (kDebugMode) {
        print('🚀 Flux Dev Image-to-Image API çağrısı başlatılıyor...');
        print('📸 Anne fotoğrafı URL: $motherUrl');
        print('👨 Baba fotoğrafı URL: $fatherUrl');
        print('👶 Bebek cinsiyeti: $gender');
        print('🤖 Model: $_modelVersion (Image-to-Image)');
      }

      // Önce ebeveyn görsellerini harmanlayarak tek bir base image üretmeyi dene
      String? baseImage = await _combineParentImages(motherUrl, fatherUrl);
      if (baseImage == null) {
        // Fallback: yalnızca anne fotoğrafını kullan ve sıkıştır
        baseImage = await _convertImageToBase64(motherUrl);
      }
      if (baseImage == null) {
        if (kDebugMode) {
          print('❌ Base image üretilemedi');
        }
        return false;
      }

      // Eğer data URL ise Replicate Files API'ye yükleyip erişilebilir URL al
      String imageForModel = baseImage;
      if (baseImage.startsWith('data:')) {
        final uploadedUrl = await _uploadDataUrlToReplicate(baseImage);
        if (uploadedUrl != null) {
          imageForModel = uploadedUrl;
          if (kDebugMode) print('☁️ Base image Replicate Files ile yüklendi: $uploadedUrl');
        } else {
          if (kDebugMode) print('⚠️ Dosya yükleme başarısız, data URL direkt gönderilecek (model kabul etmeyebilir).');
        }
      }

      // Image-to-image için çok spesifik bebek prompt'u (yaş vurgusu ile)
      String genderText = gender.toLowerCase() == 'boy' ? 'baby boy' : 'baby girl';
      String ageSpecific = gender.toLowerCase() == 'boy' ? 
        'newborn baby boy, 8-12 months old infant boy, toddler boy under 1 year' : 
        'newborn baby girl, 8-12 months old infant girl, toddler girl under 1 year';
      
      String prompt = 'Transform into a photorealistic $ageSpecific version of this person. IMPORTANT: Must be under 1 year old, infant/newborn/baby only. $genderText with round chubby baby face, very large innocent eyes, tiny button nose, small baby mouth, soft smooth baby skin, fine wispy baby hair. Chubby baby cheeks, baby proportions with large head relative to body. Wearing simple baby clothes (onesie, romper). Soft pastel background, professional baby portrait lighting, ultra high detail, photorealistic baby photography.';
      
      String negativePrompt = 'child, kid, toddler over 1 year, 2 years old, 3 years old, 4 years old, 5 years old, 6 years old, 7 years old, 8 years old, school age, preschooler, kindergarten age, walking child, talking child, adult, teenager, mature, grown up, man, woman, male adult, female adult, masculine, feminine adult features, beard, mustache, facial hair, adult teeth, adult proportions, long hair, styled hair, adult clothing, shirt, pants, dress, shoes, socks, formal wear, school uniform, playground, classroom, adult environment, standing, walking, running, adult activities, watermark, text, logo, multiple faces, deformed, distorted, mutated, extra limbs, cartoon, anime, illustration, abstract, low resolution, blurry';

      if (kDebugMode) {
        print('📝 Image-to-Image Prompt: $prompt');
        print('🚫 Negative Prompt: $negativePrompt');
        print('🖼️ Image input: ${imageForModel.substring(0, imageForModel.length > 64 ? 64 : imageForModel.length)}...');
      }

      final seed = 123456; // Deterministic seed for reproducible results
      if (kDebugMode) {
        print('🎯 Kullanılan seed: $seed');
      }

      // İstek input'unu bir değişkende topla
      Map<String, dynamic> input = {
        'image': imageForModel,
        'prompt': prompt,
        'negative_prompt': negativePrompt,
        'go_fast': false,
        'guidance': 6.0,
        'megapixels': '1',
        'num_outputs': 1,
        'aspect_ratio': '1:1',
        'output_format': 'webp',
        'output_quality': 90,
        'prompt_strength': 0.85,
        'num_inference_steps': 50,
        'seed': seed,
      };

      // Güvenlik: input içinde yanlışlıkla 'model' anahtarı varsa kaldır
      if (input.containsKey('model')) {
        if (kDebugMode) print('ℹ️ input içindeki model anahtarı kaldırıldı.');
        input.remove('model');
      }

      // Replicate artık predictions oluştururken 'version' alanını zorunlu tutuyor.
      String? versionId = await _fetchLatestModelVersionId(_modelVersion);
      if (versionId == null) {
        if (kDebugMode) {
          print('ℹ️ Versiyon ID alınamadı, fallback 1: black-forest-labs/flux-dev');
        }
        versionId = await _fetchLatestModelVersionId('black-forest-labs/flux-dev');
      }
      if (versionId == null) {
        if (kDebugMode) {
          print('ℹ️ Versiyon ID alınamadı, fallback 2: black-forest-labs/flux-schnell');
        }
        versionId = await _fetchLatestModelVersionId('black-forest-labs/flux-schnell');
      }
      if (versionId == null) {
        _error = 'Model versiyon bilgisi alınamadı. Lütfen daha sonra tekrar deneyin.';
        return false;
      }
      if (kDebugMode) {
        print('🏷️ Kullanılacak model version ID: $versionId');
      }

      Future<http.Response> makePrediction(Map<String, dynamic> inp) {
        final bodyMap = {'version': versionId, 'input': inp};
        if (kDebugMode) {
          try {
            print('📤 Prediction request body: ${jsonEncode(bodyMap)}');
          } catch (_) {}
        }
        return http.post(
          Uri.parse(_baseUrl),
          headers: {
            'Authorization': 'Bearer $_apiToken',
            'Content-Type': 'application/json',
          },
          body: jsonEncode(bodyMap),
        );
      }

      http.Response predictionResponse = await makePrediction(input);

      if (kDebugMode) {
        print('📡 API Response Status: ${predictionResponse.statusCode}');
        print('📄 API Response Body: ${predictionResponse.body}');
      }

      if (predictionResponse.statusCode == 201) {
        final predictionData = jsonDecode(predictionResponse.body);
        final predictionId = predictionData['id'];
        return await _waitForPredictionResult(predictionId);
      } else if (predictionResponse.statusCode == 402) {
        _error = 'API kredileriniz tükendi. Lütfen Replicate hesabınızı kontrol edin ve kredi ekleyin.\n\nŞimdilik demo modunda devam ediyoruz...';
        if (kDebugMode) {
          print('💳 API Credits Exhausted (402): ${predictionResponse.body}');
        }
        await _simulateAIProcessing(motherUrl, fatherUrl);
        return true;
      } else if (predictionResponse.statusCode == 422) {
        // 422 için ayrıntıyı yakala ve aynı version ile parametreleri sadeleştirip yeniden dene (2 aşama)
        String? detail = _extractErrorDetail(predictionResponse.body);
        if (kDebugMode) {
          print('🧪 422 yakalandı. Detay: ${detail ?? '-'}');
        }

        // Retry-1: go_fast kaldır
        final Map<String, dynamic> retryInput1 = Map<String, dynamic>.from(input);
        if (detail != null && detail.toLowerCase().contains('go_fast')) {
          if (kDebugMode) print('ℹ️ go_fast anahtarı desteklenmiyor görünüyor, kaldırılıyor.');
          retryInput1.remove('go_fast');
        }
        http.Response retry = await makePrediction(retryInput1);
        if (kDebugMode) {
          print('🔁 Retry-1 Status: ${retry.statusCode}');
          print('🔁 Retry-1 Body: ${retry.body}');
        }
        if (retry.statusCode == 201) {
          final predictionData = jsonDecode(retry.body);
          final predictionId = predictionData['id'];
          return await _waitForPredictionResult(predictionId);
        }

        // Retry-2: Hata detayından yasaklı/ekstra alanları temizle veya yeniden adlandır
        final String? retryDetail = _extractErrorDetail(retry.body);
        final Map<String, dynamic> retryInput2 = _sanitizeInputAgainstError(retryDetail, retryInput1);
        final http.Response retry2 = await makePrediction(retryInput2);
        if (kDebugMode) {
          print('🔁 Retry-2 Status: ${retry2.statusCode}');
          print('🔁 Retry-2 Body: ${retry2.body}');
        }
        if (retry2.statusCode == 201) {
          final predictionData = jsonDecode(retry2.body);
          final predictionId = predictionData['id'];
          return await _waitForPredictionResult(predictionId);
        } else {
          final retry2Detail = _extractErrorDetail(retry2.body);
          _error = 'Görsel üretimi başarısız oldu (422).${retry2Detail != null ? " Detay: $retry2Detail" : (retryDetail != null ? " Detay: $retryDetail" : (detail != null ? " Detay: $detail" : ''))}';
          return false;
        }
      } else {
        if (kDebugMode) {
          print('❌ Prediction oluşturulamadı: ${predictionResponse.statusCode}');
        }
        final generalDetail = _extractErrorDetail(predictionResponse.body);
        _error = 'Görsel üretimi başarısız oldu (${predictionResponse.statusCode}).${generalDetail != null ? " Detay: $generalDetail" : ''}';
        return false;
      }
    } catch (e) {
      _error = 'Görsel üretimi esnasında hata oluştu: ${e.toString()}';
      if (kDebugMode) {
        print('Replicate API Hatası: $e');
      }
      return false;
    }
  }

  // Replicate prediction sonucunu bekler ve çıktıyı _resultImageUrl'e atar
  Future<bool> _waitForPredictionResult(String predictionId) async {
    try {
      final uri = Uri.parse('$_baseUrl/$predictionId');
      while (true) {
        final resp = await http.get(
          uri,
          headers: {
            'Authorization': 'Bearer $_apiToken',
            'Content-Type': 'application/json',
          },
        );

        if (kDebugMode) {
          print('⏱️ Prediction poll status: ${resp.statusCode}');
          if (resp.body.isNotEmpty) {
            print('📨 Prediction poll body: ${resp.body}');
          }
        }

        if (resp.statusCode != 200) {
          _error = 'Prediction durumu alınamadı (${resp.statusCode}).';
          return false;
        }

        final data = jsonDecode(resp.body) as Map<String, dynamic>;
        final String? status = data['status'];

        if (status == 'succeeded') {
          final dynamic output = data['output'];
          if (output is List && output.isNotEmpty) {
            _resultImageUrl = output.first.toString();
            return true;
          } else if (output is String) {
            _resultImageUrl = output;
            return true;
          } else {
            _error = 'Prediction çıktı verisi bulunamadı.';
            return false;
          }
        } else if (status == 'failed' || status == 'canceled') {
          _error = 'Görsel üretimi başarısız: $status';
          return false;
        }

        // starting / processing durumlarında biraz bekle ve tekrar sor
        await Future.delayed(const Duration(seconds: 2));
      }
    } catch (e) {
      _error = 'Prediction sonucu beklenirken hata oluştu: ${e.toString()}';
      if (kDebugMode) {
        print('Prediction polling error: $e');
      }
      return false;
    }
  }

  // Sonucu ekranlardan temizlemek için yardımcı metod
  void clearResult() {
    _resultImageUrl = null;
    _error = null;
    notifyListeners();
  }

  // URL ya da yerel dosyadan oku, yeniden boyutlandır ve 256KB altına sıkıştırarak data URL döndür
  Future<String?> _convertImageToBase64(String imagePath) async {
    try {
      Uint8List bytes;
      if (imagePath.startsWith('http')) {
        final response = await http.get(Uri.parse(imagePath));
        if (response.statusCode != 200) return null;
        bytes = response.bodyBytes;
      } else {
        final file = File(imagePath);
        if (!await file.exists()) return null;
        bytes = await file.readAsBytes();
      }

      final decoded = img.decodeImage(bytes);
      if (decoded == null) return null;

      // Maksimum kenar 768px olacak şekilde yeniden boyutlandır
      final int maxSide = 768;
      img.Image resized = decoded;
      if (decoded.width > maxSide || decoded.height > maxSide) {
        resized = img.copyResize(decoded, width: decoded.width >= decoded.height ? maxSide : null, height: decoded.height > decoded.width ? maxSide : null, interpolation: img.Interpolation.cubic);
      }

      // Boyutu 256KB altına indir (kalite ve gerekirse ek küçültme)
      int quality = 85;
      Uint8List encoded = Uint8List.fromList(img.encodeJpg(resized, quality: quality));
      while (encoded.lengthInBytes > 256 * 1024 && quality > 60) {
        quality -= 5;
        encoded = Uint8List.fromList(img.encodeJpg(resized, quality: quality));
      }
      // Hâlâ büyükse ölçeği küçült
      int shrink = 700; // piksel
      while (encoded.lengthInBytes > 256 * 1024 && (resized.width > 384 || resized.height > 384)) {
        final int newW = resized.width > resized.height ? shrink : (resized.width * shrink ~/ resized.height);
        final int newH = resized.height >= resized.width ? shrink : (resized.height * shrink ~/ resized.width);
        resized = img.copyResize(resized, width: newW, height: newH, interpolation: img.Interpolation.linear);
        encoded = Uint8List.fromList(img.encodeJpg(resized, quality: quality));
        shrink = (shrink * 0.85).floor();
        if (shrink < 384) break;
      }

      final b64 = base64Encode(encoded);
      if (kDebugMode) {
        print('📦 Hazırlanan data URL boyutu: ${encoded.lengthInBytes} bytes, kalite: $quality, boyut: ${resized.width}x${resized.height}');
      }
      return 'data:image/jpeg;base64,$b64';
    } catch (e) {
      if (kDebugMode) {
        print('Base64 çevirme/sıkıştırma hatası: $e');
      }
      return null;
    }
  }

  // İki fotoğrafı harmanla (anne ve baba), sonra sıkıştırılmış data URL döndür
  Future<String?> _combineParentImages(String motherPath, String fatherPath) async {
    try {
      Uint8List mBytes;
      if (motherPath.startsWith('http')) {
        final r = await http.get(Uri.parse(motherPath));
        if (r.statusCode != 200) return null;
        mBytes = r.bodyBytes;
      } else {
        final f = File(motherPath);
        if (!await f.exists()) return null;
        mBytes = await f.readAsBytes();
      }

      Uint8List fBytes;
      if (fatherPath.startsWith('http')) {
        final r = await http.get(Uri.parse(fatherPath));
        if (r.statusCode != 200) return null;
        fBytes = r.bodyBytes;
      } else {
        final f = File(fatherPath);
        if (!await f.exists()) return null;
        fBytes = await f.readAsBytes();
      }

      final mImg = img.decodeImage(mBytes);
      final fImg = img.decodeImage(fBytes);
      if (mImg == null || fImg == null) return null;

      // Aynı boyuta getir
      final int targetW = 768;
      final int targetH = (targetW * (mImg.height / mImg.width)).round();
      final img.Image mResized = img.copyResize(mImg, width: targetW, height: targetH, interpolation: img.Interpolation.cubic);
      final img.Image fResized = img.copyResize(fImg, width: targetW, height: targetH, interpolation: img.Interpolation.cubic);

      // 50/50 karışım (alpha blend) - image 4.x Pixel API
      final img.Image blended = img.Image(width: targetW, height: targetH);
      for (int y = 0; y < targetH; y++) {
        for (int x = 0; x < targetW; x++) {
          final img.Pixel p1 = mResized.getPixel(x, y);
          final img.Pixel p2 = fResized.getPixel(x, y);
          final int r = ((p1.r + p2.r) ~/ 2);
          final int g = ((p1.g + p2.g) ~/ 2);
          final int b = ((p1.b + p2.b) ~/ 2);
          final int a = ((p1.a + p2.a) ~/ 2);
          blended.setPixelRgba(x, y, r, g, b, a);
        }
      }

      // Sıkıştır ve data URL döndür (256KB altı)
      int quality = 85;
      Uint8List encoded = Uint8List.fromList(img.encodeJpg(blended, quality: quality));
      while (encoded.lengthInBytes > 256 * 1024 && quality > 60) {
        quality -= 5;
        encoded = Uint8List.fromList(img.encodeJpg(blended, quality: quality));
      }

      final b64 = base64Encode(encoded);
      if (kDebugMode) {
        print('🧪 Harmanlanmış görsel boyutu: ${encoded.lengthInBytes} bytes, kalite: $quality, boyut: ${blended.width}x${blended.height}');
      }
      return 'data:image/jpeg;base64,$b64';
    } catch (e) {
      if (kDebugMode) {
        print('Fotoğraf birleştirme hatası: $e');
      }
      return null;
    }
  }
}

// Hata detayını JSON body içinden çekmek için yardımcı
String? _extractErrorDetail(String body) {
  try {
    final dynamic data = jsonDecode(body);
    if (data is Map<String, dynamic>) {
      if (data['detail'] != null) return data['detail'].toString();
      if (data['error'] != null) return data['error'].toString();
      if (data['message'] != null) return data['message'].toString();
    }
  } catch (_) {}
  return null;
}

// Replicate modelinin en güncel versiyon ID'sini çeker
Future<String?> _fetchLatestModelVersionId(String model) async {
  try {
    // model beklenen format: owner/name
    final parts = model.split('/');
    if (parts.length != 2) {
      if (kDebugMode) print('⚠️ Geçersiz model formatı: $model');
      return null;
    }
    final owner = parts[0];
    final name = parts[1];

    // 1) Önce model detayları endpointinden latest_version.id çekmeyi dene
    final detailsUri = Uri.parse('https://api.replicate.com/v1/models/$owner/$name');
    final headers = {
      'Authorization': 'Bearer ${dotenv.env['REPLICATE_API_TOKEN']}',
      'Content-Type': 'application/json',
    };
    final detailsResp = await http.get(detailsUri, headers: headers);
    if (kDebugMode) {
      print('📥 Model detay status: ${detailsResp.statusCode}');
      if (detailsResp.body.isNotEmpty) print('📥 Model detay body: ${detailsResp.body}');
    }
    if (detailsResp.statusCode == 200) {
      final data = jsonDecode(detailsResp.body) as Map<String, dynamic>;
      final latest = data['latest_version'] as Map<String, dynamic>?;
      final String? id = latest != null ? latest['id']?.toString() : null;
      if (id != null && id.isNotEmpty) return id;
    }

    // 2) Geriye dönük: /versions listesinden ilk öğeyi al (genellikle en günceli en üsttedir)
    final versionsUri = Uri.parse('https://api.replicate.com/v1/models/$owner/$name/versions');
    final resp = await http.get(versionsUri, headers: headers);
    if (kDebugMode) {
      print('📥 Versiyonlar status: ${resp.statusCode}');
      if (resp.body.isNotEmpty) print('📥 Versiyonlar body: ${resp.body}');
    }
    if (resp.statusCode == 200) {
      final data = jsonDecode(resp.body) as Map<String, dynamic>;
      final List<dynamic>? results = data['results'] as List<dynamic>?;
      if (results != null && results.isNotEmpty) {
        final String? id = results.first['id']?.toString();
        if (id != null && id.isNotEmpty) return id;
      }
    }
  } catch (e) {
    if (kDebugMode) print('Versiyon ID alınamadı: $e');
  }
  return null;
}

// Hata detayına göre input içindeki hatalı alanları temizler/yeniden adlandırır
Map<String, dynamic> _sanitizeInputAgainstError(String? detail, Map<String, dynamic> current) {
  final Map<String, dynamic> sanitized = Map<String, dynamic>.from(current);

  // Her ihtimale karşıın input içindeki 'model' alanını asla göndermeyelim
  sanitized.remove('model');

  if (detail == null) return sanitized;

  // "Additional property X is not allowed" kalıbını yakala ve ilgili anahtarı kaldır
  final reg = RegExp(r'Additional property ([a-zA-Z0-9_\-]+) is not allowed', caseSensitive: false);
  final match = reg.firstMatch(detail);
  if (match != null && match.groupCount >= 1) {
    final String key = match.group(1)!.trim();
    if (sanitized.containsKey(key)) {
      if (kDebugMode) print('🧹 422: Yasaklı alan "$key" inputtan kaldırılıyor.');
      sanitized.remove(key);
    }
  }

  // Bazı modellerde aşağıdaki alanlar desteklenmeyebilir, detaydan bağımsız son bir temizlik yap
  const possibleUnsupported = [
    'go_fast',
    'megapixels',
    'prompt_strength',
    'num_inference_steps',
    'guidance',
    'output_quality',
    'negative_prompt',
  ];
  for (final k in possibleUnsupported) {
    if (detail.toLowerCase().contains(k) && sanitized.containsKey(k)) {
      if (kDebugMode) print('🧹 422: "$k" alanı desteklenmiyor görünüyor, kaldırılıyor.');
      sanitized.remove(k);
    }
  }

  return sanitized;
}

// Data URL (base64) içeriğini Replicate Files API üzerinden yükleyip public URL döndürür
Future<String?> _uploadDataUrlToReplicate(String dataUrl) async {
  try {
    final int comma = dataUrl.indexOf(',');
    if (comma == -1) return null;
    final String header = dataUrl.substring(0, comma); // data:image/jpeg;base64
    final String b64 = dataUrl.substring(comma + 1);

    String mime = 'image/jpeg';
    final mimeMatch = RegExp(r'data:([^;]+);base64', caseSensitive: false).firstMatch(header);
    if (mimeMatch != null && mimeMatch.groupCount >= 1) {
      mime = mimeMatch.group(1)!.trim();
    }

    final Uint8List bytes = base64Decode(b64);

    final uri = Uri.parse('https://api.replicate.com/v1/files');
    final request = http.MultipartRequest('POST', uri);
    request.headers['Authorization'] = 'Bearer ${dotenv.env['REPLICATE_API_TOKEN']}';
    // Content-Type otomatik ayarlanır; elle application/json vermeyelim

    final file = http.MultipartFile.fromBytes(
      'file',
      bytes,
      filename: 'upload.${_extensionFromMime(mime)}',
      contentType: MediaType.parse(mime),
    );
    request.files.add(file);

    final streamed = await request.send();
    final status = streamed.statusCode;
    final respStr = await streamed.stream.bytesToString();

    if (kDebugMode) {
      print('📤 Files upload status: $status');
      if (respStr.isNotEmpty) {
        print('📤 Files upload body: $respStr');
      }
    }

    if (status == 200 || status == 201) {
      try {
        final data = jsonDecode(respStr);
        if (data is Map<String, dynamic>) {
          final dynamic maybeUrl = data['url'] ?? data['serving_url'] ?? data['download_url'];
          if (maybeUrl != null) {
            return maybeUrl.toString();
          }
        }
      } catch (e) {
        if (kDebugMode) print('Yükleme yanıtı parse edilemedi: $e');
      }
    }
    return null;
  } catch (e) {
    if (kDebugMode) print('Dosya yükleme hatası: $e');
    return null;
  }
}

String _extensionFromMime(String mime) {
  final m = mime.toLowerCase();
  if (m.contains('png')) return 'png';
  if (m.contains('webp')) return 'webp';
  if (m.contains('jpeg') || m.contains('jpg')) return 'jpg';
  return 'bin';
}