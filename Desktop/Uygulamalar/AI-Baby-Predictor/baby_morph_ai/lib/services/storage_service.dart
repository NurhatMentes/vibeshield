import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:firebase_storage/firebase_storage.dart';
import 'package:image_picker/image_picker.dart';

class StorageService extends ChangeNotifier {
  final FirebaseStorage _storage = FirebaseStorage.instance;
  final ImagePicker _picker = ImagePicker();
  
  bool _isUploading = false;
  double _uploadProgress = 0.0;

  bool get isUploading => _isUploading;
  double get uploadProgress => _uploadProgress;

  Future<XFile?> pickImageFromCamera() async {
    try {
      final XFile? image = await _picker.pickImage(
        source: ImageSource.camera,
        maxWidth: 1024,
        maxHeight: 1024,
        imageQuality: 80,
      );
      return image;
    } catch (e) {
      return null;
    }
  }

  Future<XFile?> pickImageFromGallery() async {
    try {
      final XFile? image = await _picker.pickImage(
        source: ImageSource.gallery,
        maxWidth: 1024,
        maxHeight: 1024,
        imageQuality: 80,
      );
      return image;
    } catch (e) {
      return null;
    }
  }

  Future<String?> uploadImage(File imageFile, String userId) async {
    try {
      _isUploading = true;
      _uploadProgress = 0.0;
      notifyListeners();

      final String fileName = 'photos/${userId}/${DateTime.now().millisecondsSinceEpoch}.jpg';
      final Reference ref = _storage.ref().child(fileName);
      
      final UploadTask uploadTask = ref.putFile(imageFile);
      
      uploadTask.snapshotEvents.listen((TaskSnapshot snapshot) {
        _uploadProgress = snapshot.bytesTransferred / snapshot.totalBytes;
        notifyListeners();
      });

      final TaskSnapshot snapshot = await uploadTask;
      final String downloadUrl = await snapshot.ref.getDownloadURL();
      
      _isUploading = false;
      _uploadProgress = 0.0;
      notifyListeners();
      
      return downloadUrl;
    } catch (e) {
      _isUploading = false;
      _uploadProgress = 0.0;
      notifyListeners();
      return null;
    }
  }

  Future<void> deleteImage(String imageUrl) async {
    try {
      final Reference ref = _storage.refFromURL(imageUrl);
      await ref.delete();
    } catch (e) {
      // Silme hatası
    }
  }
}