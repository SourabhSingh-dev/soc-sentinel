import joblib
import numpy as np
import scipy.sparse as sp
import polars as pl
import shap

class ThreatTriageEngine:
    def __init__(self,model_dir : str):

        print("Initializing Threat Triage Engine...")
        self.calibrated_xgb = joblib.load(f"{model_dir}/calibrated_xgb_model.joblib")
        self.raw_xgb = joblib.load(f"{model_dir}/xgb_fused_model.joblib")
        self.explainer = shap.TreeExplainer(self.raw_xgb)

        self.tfidf_alert = joblib.load(f"{model_dir}/tfidf_alert.joblib")
        self.tfidf_file = joblib.load(f"{model_dir}/tfidf_file.joblib")

        self.feature_names = []

## Will do it tomorrow
