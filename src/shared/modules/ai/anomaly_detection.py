import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.preprocessing import StandardScaler
from typing import List, Tuple, Dict
from dataclasses import dataclass

@dataclass
class TrainingConfig:
    batch_size: int = 32
    epochs: int = 20
    learning_rate: float = 0.001
    early_stopping_patience: int = 5

class SecurityDataset(Dataset):
    def __init__(self, features: np.ndarray, labels: np.ndarray):
        self.features = torch.FloatTensor(features)
        self.labels = torch.FloatTensor(labels)
        
    def __len__(self):
        return len(self.features)
    
    def __getitem__(self, idx):
        return self.features[idx], self.labels[idx]

class AttentionLSTM(nn.Module):
    def __init__(self, input_dim: int = 10, hidden_dim: int = 64):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, batch_first=True, bidirectional=True)
        self.attention = nn.Sequential(
            nn.Linear(hidden_dim*2, hidden_dim),
            nn.Tanh(),
            nn.Linear(hidden_dim, 1, bias=False)
        )  # Eksik parantez eklendi
        self.classifier = nn.Linear(hidden_dim*2, 1)
        
    def forward(self, x):
        lstm_out, _ = self.lstm(x)
        attention_weights = torch.softmax(self.attention(lstm_out), dim=1)
        context = torch.sum(attention_weights * lstm_out, dim=1)
        return torch.sigmoid(self.classifier(context))

class AnomalyDetector:
    def __init__(self, config: TrainingConfig = TrainingConfig()):
        self.config = config
        self.scaler = StandardScaler()
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = AttentionLSTM().to(self.device)
        self.criterion = nn.BCELoss()
        self.optimizer = torch.optim.AdamW(
            self.model.parameters(), 
            lr=config.learning_rate
        )
    
    def train(self, X: List[List[float]], y: List[int]) -> Dict:
        # Giriş verilerini kontrol et
        if len(X) != len(y):
            raise ValueError("X ve y boyutları eşleşmiyor")
            
        X_scaled = self.scaler.fit_transform(np.array(X))
        dataset = SecurityDataset(X_scaled, np.array(y))
        loader = DataLoader(dataset, batch_size=self.config.batch_size, shuffle=True)
        
        best_loss = float('inf')
        patience_counter = 0
        
        for epoch in range(self.config.epochs):
            self.model.train()
            epoch_loss = 0.0
            
            for batch_X, batch_y in loader:
                # Verileri uygun şekle getir
                batch_X = batch_X.unsqueeze(1).to(self.device)  # [batch, 1, features]
                batch_y = batch_y.unsqueeze(1).to(self.device)  # [batch, 1]
                
                self.optimizer.zero_grad()
                outputs = self.model(batch_X)
                loss = self.criterion(outputs, batch_y)
                loss.backward()
                self.optimizer.step()
                
                epoch_loss += loss.item()
            
            avg_loss = epoch_loss / len(loader)
            print(f"Epoch {epoch+1}/{self.config.epochs} - Loss: {avg_loss:.4f}")
            
            # Early stopping kontrolü
            if avg_loss < best_loss:
                best_loss = avg_loss
                patience_counter = 0
            else:
                patience_counter += 1
                if patience_counter >= self.config.early_stopping_patience:
                    print("Early stopping triggered")
                    break
        
        return {
            "final_loss": avg_loss,
            "status": "completed",
            "best_loss": best_loss
        }

    def detect(self, data: List[float]) -> Tuple[str, float]:
        if not isinstance(data, list) or len(data) == 0:
            raise ValueError("Geçersiz giriş verisi")
            
        self.model.eval()
        with torch.no_grad():
            scaled = self.scaler.transform([data])
            tensor = torch.FloatTensor(scaled).unsqueeze(0).unsqueeze(0).to(self.device)
            proba = self.model(tensor).item()
            return ("ATTACK" if proba > 0.9 else "NORMAL", proba)
    
    def save_model(self, path: str):
        torch.save({
            'model_state_dict': self.model.state_dict(),
            'scaler_mean': self.scaler.mean_,
            'scaler_scale': self.scaler.scale_
        }, path)
    
    def load_model(self, path: str):
        checkpoint = torch.load(path)
        self.model.load_state_dict(checkpoint['model_state_dict'])
        self.scaler.mean_ = checkpoint['scaler_mean']
        self.scaler.scale_ = checkpoint['scaler_scale']