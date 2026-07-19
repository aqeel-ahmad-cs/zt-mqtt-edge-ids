"""
Converts raw flow-tracker feature dicts into the numeric matrix the model
expects, and owns the fitted scaler. This lives separately from the model
code because the exact same transform has to be applied identically at
training time and inference time - keeping it in one place is the only
way to guarantee that.
"""

import logging

import numpy as np

logger = logging.getLogger(__name__)

# order matters - this defines the column layout every downstream
# model file assumes. client_id/source_ip are identity fields, not
# features, and are stripped before this list is used.
FEATURE_COLUMNS = [
    "mean_inter_arrival",
    "inter_arrival_variance",
    "mean_payload_length",
    "max_payload_length",
    "payload_length_std",
    "topic_cardinality",
    "connect_to_publish_ratio",
    "malformed_packet_count",
    "mean_keep_alive",
]


def feature_dict_to_vector(feature_dict: dict) -> np.ndarray:
    """
    Pulls the model-relevant columns out of a flow tracker feature dict
    in the fixed order the model was trained on. Missing keys default to
    0.0 rather than raising, since a partially-formed window (e.g. one
    with no malformed packets) legitimately won't have every field.
    """
    try:
        values = [float(feature_dict.get(col, 0.0)) for col in FEATURE_COLUMNS]
    except (TypeError, ValueError) as exc:
        logger.error("could not coerce feature dict to floats: %s (dict=%s)", exc, feature_dict)
        raise

    return np.array(values, dtype=np.float64).reshape(1, -1)


def dataframe_to_matrix(df):
    """Same idea as feature_dict_to_vector but for a batch of rows (training path)."""
    missing = [col for col in FEATURE_COLUMNS if col not in df.columns]
    if missing:
        raise ValueError(f"training dataframe is missing required columns: {missing}")

    return df[FEATURE_COLUMNS].to_numpy(dtype=np.float64)
