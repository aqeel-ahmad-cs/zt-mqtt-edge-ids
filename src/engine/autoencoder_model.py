"""
Optional autoencoder-based detector, offered as an alternative backend to
the Isolation Forest for cases where the feature distribution is nonlinear
enough that a tree-based partitioning approach underperforms. Not the
default because it needs more training data and more tuning to be
reliable on a small lab dataset, but the interface mirrors
AnomalyDetector so the two are interchangeable from the caller's side.
"""

import logging
import os

import numpy as np
import torch
import torch.nn as nn

logger = logging.getLogger(__name__)


class _AutoencoderNet(nn.Module):
    def __init__(self, input_dim: int, latent_dim: int = 4):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 16),
            nn.ReLU(),
            nn.Linear(16, latent_dim),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 16),
            nn.ReLU(),
            nn.Linear(16, input_dim),
        )

    def forward(self, x):
        latent = self.encoder(x)
        return self.decoder(latent)


class AutoencoderDetector:
    def __init__(self, input_dim: int, latent_dim: int = 4, learning_rate: float = 1e-3):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.net = _AutoencoderNet(input_dim, latent_dim).to(self.device)
        self.optimizer = torch.optim.Adam(self.net.parameters(), lr=learning_rate)
        self.loss_fn = nn.MSELoss()
        self.reconstruction_threshold = None
        self._is_fitted = False

    def fit(self, X: np.ndarray, epochs: int = 60, batch_size: int = 32, threshold_percentile: float = 95.0):
        if X.shape[0] < 20:
            raise ValueError(f"need at least 20 samples to train the autoencoder, got {X.shape[0]}")

        tensor_X = torch.tensor(X, dtype=torch.float32).to(self.device)
        dataset = torch.utils.data.TensorDataset(tensor_X)
        loader = torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True)

        self.net.train()
        for epoch in range(epochs):
            epoch_loss = 0.0
            for (batch,) in loader:
                self.optimizer.zero_grad()
                reconstruction = self.net(batch)
                loss = self.loss_fn(reconstruction, batch)
                loss.backward()
                self.optimizer.step()
                epoch_loss += loss.item() * batch.size(0)

            if (epoch + 1) % 10 == 0:
                logger.info("autoencoder epoch %d/%d - avg loss %.6f",
                            epoch + 1, epochs, epoch_loss / X.shape[0])

        # threshold is derived from the training set's own reconstruction
        # error distribution rather than a fixed constant, since payload
        # scale varies a lot between deployments
        self.net.eval()
        with torch.no_grad():
            reconstructions = self.net(tensor_X)
            errors = torch.mean((reconstructions - tensor_X) ** 2, dim=1).cpu().numpy()

        self.reconstruction_threshold = float(np.percentile(errors, threshold_percentile))
        self._is_fitted = True
        logger.info("autoencoder fitted, reconstruction threshold set to %.6f", self.reconstruction_threshold)

    def score(self, X: np.ndarray) -> np.ndarray:
        if not self._is_fitted:
            raise RuntimeError("autoencoder has not been fitted or loaded yet")

        self.net.eval()
        tensor_X = torch.tensor(X, dtype=torch.float32).to(self.device)
        with torch.no_grad():
            reconstruction = self.net(tensor_X)
            errors = torch.mean((reconstruction - tensor_X) ** 2, dim=1).cpu().numpy()

        # invert sign so lower = more anomalous, matching the Isolation
        # Forest convention used elsewhere in this codebase
        return self.reconstruction_threshold - errors

    def save(self, model_path: str):
        if not self._is_fitted:
            raise RuntimeError("refusing to save an unfitted autoencoder")
        try:
            os.makedirs(os.path.dirname(model_path), exist_ok=True)
            torch.save({
                "state_dict": self.net.state_dict(),
                "threshold": self.reconstruction_threshold,
            }, model_path)
            logger.info("saved autoencoder weights to %s", model_path)
        except OSError as exc:
            logger.error("failed saving autoencoder: %s", exc)
            raise

    def load(self, model_path: str):
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"autoencoder artifact missing: {model_path}")
        try:
            checkpoint = torch.load(model_path, map_location=self.device)
            self.net.load_state_dict(checkpoint["state_dict"])
            self.reconstruction_threshold = checkpoint["threshold"]
            self._is_fitted = True
            logger.info("loaded autoencoder from %s", model_path)
        except (OSError, RuntimeError, KeyError) as exc:
            logger.error("failed loading autoencoder checkpoint: %s", exc)
            raise
