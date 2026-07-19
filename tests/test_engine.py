import sys
import os

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.engine.isolation_forest_model import AnomalyDetector
from src.engine.preprocessing import FEATURE_COLUMNS, dataframe_to_matrix, feature_dict_to_vector


class TestPreprocessing:
    def test_feature_dict_to_vector_preserves_column_order(self):
        feature_dict = {col: float(i) for i, col in enumerate(FEATURE_COLUMNS)}
        vector = feature_dict_to_vector(feature_dict)

        assert vector.shape == (1, len(FEATURE_COLUMNS))
        assert list(vector[0]) == [float(i) for i in range(len(FEATURE_COLUMNS))]

    def test_missing_keys_default_to_zero(self):
        partial_dict = {"mean_inter_arrival": 1.5}
        vector = feature_dict_to_vector(partial_dict)

        assert vector.shape == (1, len(FEATURE_COLUMNS))
        assert vector[0][0] == 1.5
        assert vector[0][1] == 0.0

    def test_dataframe_to_matrix_raises_on_missing_columns(self):
        df = pd.DataFrame({"mean_inter_arrival": [1.0, 2.0]})
        with pytest.raises(ValueError):
            dataframe_to_matrix(df)

    def test_dataframe_to_matrix_returns_correct_shape(self):
        df = pd.DataFrame({col: [1.0, 2.0, 3.0] for col in FEATURE_COLUMNS})
        matrix = dataframe_to_matrix(df)
        assert matrix.shape == (3, len(FEATURE_COLUMNS))


class TestAnomalyDetector:
    def _make_baseline_matrix(self, n_samples=100, seed=42):
        rng = np.random.default_rng(seed)
        # tight cluster around a fixed point simulates well-behaved baseline traffic
        return rng.normal(loc=2.0, scale=0.3, size=(n_samples, len(FEATURE_COLUMNS)))

    def test_fit_raises_on_too_few_samples(self):
        detector = AnomalyDetector()
        tiny_matrix = np.random.rand(3, len(FEATURE_COLUMNS))
        with pytest.raises(ValueError):
            detector.fit(tiny_matrix)

    def test_score_raises_before_fit(self):
        detector = AnomalyDetector()
        matrix = np.random.rand(5, len(FEATURE_COLUMNS))
        with pytest.raises(RuntimeError):
            detector.score(matrix)

    def test_fitted_model_scores_outlier_lower_than_inlier(self):
        detector = AnomalyDetector(n_estimators=100, contamination=0.05, random_state=1)
        baseline = self._make_baseline_matrix()
        detector.fit(baseline)

        inlier = np.array([[2.0] * len(FEATURE_COLUMNS)])
        outlier = np.array([[50.0] * len(FEATURE_COLUMNS)])

        inlier_score = detector.score(inlier)[0]
        outlier_score = detector.score(outlier)[0]

        assert outlier_score < inlier_score

    def test_save_and_load_round_trip(self, tmp_path):
        detector = AnomalyDetector(random_state=1)
        baseline = self._make_baseline_matrix()
        detector.fit(baseline)

        model_path = str(tmp_path / "model.joblib")
        scaler_path = str(tmp_path / "scaler.joblib")
        detector.save(model_path, scaler_path)

        reloaded = AnomalyDetector()
        reloaded.load(model_path, scaler_path)

        sample = np.array([[2.0] * len(FEATURE_COLUMNS)])
        original_score = detector.score(sample)
        reloaded_score = reloaded.score(sample)

        assert np.isclose(original_score, reloaded_score)

    def test_save_before_fit_raises(self, tmp_path):
        detector = AnomalyDetector()
        with pytest.raises(RuntimeError):
            detector.save(str(tmp_path / "model.joblib"), str(tmp_path / "scaler.joblib"))
