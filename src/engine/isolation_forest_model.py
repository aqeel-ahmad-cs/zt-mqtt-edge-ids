"""
Isolation Forest anomaly detector - the primary detection model for this
project. Chosen over a supervised classifier because we don't have (and
don't want to depend on having) labeled attack traffic from every possible
IoT deployment; isolation forests only need a baseline of normal behaviour
to learn what "easy to isolate" looks like in feature space.
"""

import logging
import os

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)


class AnomalyDetector:
    def __init__(self, n_estimators: int = 200, contamination: float = 0.05, random_state: int = 42):
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )
        self.scaler = StandardScaler()
        self._is_fitted = False

    def fit(self, X: np.ndarray):
        if X.shape[0] < 10:
            raise ValueError(
                f"refusing to fit on {X.shape[0]} samples - need a larger baseline "
                "or the model will overfit noise as the decision boundary"
            )

        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self._is_fitted = True
        logger.info("isolation forest fitted on %d samples, %d features", *X.shape)

    def score(self, X: np.ndarray) -> np.ndarray:
        """
        Returns the raw decision_function output - lower (more negative)
        means more anomalous. We expose the raw score rather than just the
        -1/1 predict() label so the mitigation layer can apply its own
        threshold and smoothing logic instead of being locked into
        scikit-learn's default contamination-based cutoff.
        """
        if not self._is_fitted:
            raise RuntimeError("model has not been fitted or loaded yet")

        try:
            X_scaled = self.scaler.transform(X)
        except ValueError as exc:
            logger.error("feature shape mismatch during scoring: %s", exc)
            raise

        return self.model.decision_function(X_scaled)

    def predict_label(self, X: np.ndarray) -> np.ndarray:
        """Convenience wrapper returning sklearn's own -1/1 anomaly labels."""
        if not self._is_fitted:
            raise RuntimeError("model has not been fitted or loaded yet")
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)

    def save(self, model_path: str, scaler_path: str):
        if not self._is_fitted:
            raise RuntimeError("refusing to save an unfitted model")

        try:
            os.makedirs(os.path.dirname(model_path), exist_ok=True)
            joblib.dump(self.model, model_path)
            joblib.dump(self.scaler, scaler_path)
            logger.info("saved model to %s, scaler to %s", model_path, scaler_path)
        except OSError as exc:
            logger.error("failed writing model artifacts to disk: %s", exc)
            raise

    def load(self, model_path: str, scaler_path: str):
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"model artifact missing: {model_path}")
        if not os.path.exists(scaler_path):
            raise FileNotFoundError(f"scaler artifact missing: {scaler_path}")

        try:
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self._is_fitted = True
            logger.info("loaded model from %s", model_path)
        except (OSError, EOFError) as exc:
            logger.error("failed loading model artifacts: %s", exc)
            raise
