import 'dart:convert';
import 'dart:io';
import 'package:http/http.dart' as http;

void main() async {
  // API token'ınızı buraya girin
  const String apiToken = 'YOUR_API_TOKEN_HERE';
  
  print('🧪 Replicate API Test Başlatılıyor...\n');
  
  // Test 1: Baby Mystic Model Test
  await testBabyMysticModel(apiToken);
  
  // Test 2: Mevcut Model Test (karşılaştırma için)
  await testCurrentModel(apiToken);
}

Future<void> testBabyMysticModel(String apiToken) async {
  print('📱 Test 1: Baby Mystic Model');
  print('Model: smoosh-sh/baby-mystic');
  print('Version: ba5ab694a9df055fa469e55eeab162cc288039da0abd8b19d956980cc3b49f6d');
  
  try {
    final response = await http.post(
      Uri.parse('https://api.replicate.com/v1/predictions'),
      headers: {
        'Authorization': 'Token $apiToken',
        'Content-Type': 'application/json',
      },
      body: jsonEncode({
        'version': 'ba5ab694a9df055fa469e55eeab162cc288039da0abd8b19d956980cc3b49f6d',
        'input': {
          'image': 'https://replicate.delivery/pbxt/KFPRlN6xTao1tNR3ZipEQls5QeadsPtC54el8CVGvWn1l1PH/dad2.png', // Test erkek fotoğrafı
          'image2': 'https://replicate.delivery/pbxt/KFPRm9acpMYUgAaEI1Fi0FZEiDWDyiPVL9tcI6XYT4vS0EgS/mom2.png', // Test kadın fotoğrafı
          'gender': 'boy',
          'steps': 25,
          'width': 512,
          'height': 728,
        }
      }),
    );
    
    print('Status Code: ${response.statusCode}');
    print('Response: ${response.body}\n');
    
    if (response.statusCode == 201) {
      print('✅ Baby Mystic Model: API çağrısı başarılı!');
      final data = jsonDecode(response.body);
      print('Prediction ID: ${data['id']}');
    } else if (response.statusCode == 402) {
      print('💳 Baby Mystic Model: API kredisi yetersiz (402)');
    } else {
      print('❌ Baby Mystic Model: Hata - ${response.statusCode}');
    }
  } catch (e) {
    print('❌ Baby Mystic Model: Exception - $e');
  }
  
  print('─' * 50);
}

Future<void> testCurrentModel(String apiToken) async {
  print('📱 Test 2: Mevcut Model (Karşılaştırma)');
  print('Model: lucataco/realistic-vision-v5.1-img2img');
  
  try {
    final response = await http.post(
      Uri.parse('https://api.replicate.com/v1/predictions'),
      headers: {
        'Authorization': 'Token $apiToken',
        'Content-Type': 'application/json',
      },
      body: jsonEncode({
        'version': '15a3689ee13b0d2616e98820eca31d4c3abcd36672df6afce5cb6feb1d66087d',
        'input': {
          'image': 'https://example.com/test.jpg',
          'prompt': 'a baby',
          'num_inference_steps': 20,
          'guidance_scale': 7.5,
          'strength': 0.8,
        }
      }),
    );
    
    print('Status Code: ${response.statusCode}');
    print('Response: ${response.body}\n');
    
    if (response.statusCode == 201) {
      print('✅ Mevcut Model: API çağrısı başarılı!');
      final data = jsonDecode(response.body);
      print('Prediction ID: ${data['id']}');
    } else if (response.statusCode == 402) {
      print('💳 Mevcut Model: API kredisi yetersiz (402)');
    } else {
      print('❌ Mevcut Model: Hata - ${response.statusCode}');
    }
  } catch (e) {
    print('❌ Mevcut Model: Exception - $e');
  }
  
  print('─' * 50);
}