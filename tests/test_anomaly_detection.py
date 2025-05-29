import pytest
import numpy as np
import torch  # Eksik olan torch importu eklendi
from src.modules.ai.anomaly_detection import AnomalyDetector, SecurityDataset

@pytest.fixture
def sample_data():
    # Daha anlamlı test verisi oluşturuyoruz
    normal_data = np.random.normal(loc=0, scale=1, size=(90, 10))
    anomaly_data = np.random.normal(loc=5, scale=3, size=(10, 10))  # Anomaliler
    X = np.vstack([normal_data, anomaly_data]).tolist()
    y = [0]*90 + [1]*10  # 10% anomalies
    return X, y

def test_dataset_creation(sample_data):
    X, y = sample_data
    dataset = SecurityDataset(X, y)
    
    # Dataset boyut kontrolü
    assert len(dataset) == 100
    
    # Örnek veri şekil kontrolü
    sample_feature, sample_label = dataset[0]
    assert isinstance(sample_feature, torch.Tensor)
    assert isinstance(sample_label, torch.Tensor)
    assert sample_feature.shape == torch.Size([10])  # 10 özellikli veri
    assert sample_label.shape == torch.Size([])  # Skaler label

def test_anomaly_detector_training(sample_data):
    X, y = sample_data
    detector = AnomalyDetector()
    
    # Eğitim öncesi model parametreleri
    initial_params = [p.clone() for p in detector.model.parameters()]
    
    results = detector.train(X, y)
    
    # Eğitim sonrası model parametreleri
    trained_params = [p for p in detector.model.parameters()]
    
    # Sonuç kontrolü
    assert "final_loss" in results
    assert isinstance(results["final_loss"], float)
    assert results["final_loss"] > 0  # Loss pozitif olmalı
    
    # Modelin gerçekten öğrenip öğrenmediğini kontrol
    for initial, trained in zip(initial_params, trained_params):
        assert not torch.equal(initial, trained)  # Parametreler değişmeli

def test_anomaly_detection(sample_data):
    X, y = sample_data
    detector = AnomalyDetector()
    detector.train(X, y)  # Modeli önce eğitiyoruz
    
    # Test verisi oluştur
    test_normal = np.random.normal(loc=0, scale=1, size=10).tolist()
    test_anomaly = np.random.normal(loc=10, scale=5, size=10).tolist()  # Belirgin anomali
    
    # Tahmin yap
    normal_result, normal_proba = detector.detect(test_normal)
    anomaly_result, anomaly_proba = detector.detect(test_anomaly)
    
    # Kontroller
    assert normal_result == "NORMAL"
    assert anomaly_result == "ATTACK"
    assert 0 <= normal_proba <= 1
    assert 0 <= anomaly_proba <= 1
    assert anomaly_proba > normal_proba  # Anomali daha yüksek olasılıkta olmalı