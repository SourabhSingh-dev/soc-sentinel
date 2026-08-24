import joblib
import numpy as np
import scipy.sparse as sp
import polars as pl
import shap
import json

def space_tokenizer(x):
    return str(x).split()

class ThreatTriageEngine:
    def __init__(self,model_dir : str):

        print("Initializing Threat Triage Engine...")
        self.calibrated_xgb = joblib.load(f"{model_dir}/calibrated_xgb_model.joblib")
        self.raw_xgb = joblib.load(f"{model_dir}/xgb_fused_model.joblib")
        self.explainer = shap.TreeExplainer(self.raw_xgb)

        self.tfidf_alert = joblib.load(f"{model_dir}/tfidf_alert_vectorizer.joblib")
        self.tfidf_file = joblib.load(f"{model_dir}/tfidf_file_vectorizer.joblib")

        self.feature_names = []

    def _preprocess(self,raw_incidents) -> sp.csr_matrix: 

        if isinstance(raw_incidents,pl.DataFrame):
            lf = raw_incidents.lazy()
        elif isinstance(raw_incidents, list):
            lf = pl.DataFrame(raw_incidents,infer_schema_length=None).lazy()
        else:
            raise TypeError(
            "raw_incidents must be a Polars DataFrame "
            "or a list of dictionaries"
        )
        features_to_count = [
            'AlertId', 'DetectorId', 'AlertTitle', 'Category', 'EntityType', 'EvidenceRole', 
            'DeviceId', 'Sha256', 'IpAddress', 'Url', 'AccountSid', 'AccountUpn', 'AccountObjectId', 
            'AccountName', 'DeviceName', 'NetworkMessageId', 'RegistryKey', 'RegistryValueName', 
            'RegistryValueData', 'ApplicationId', 'ApplicationName', 'OAuthApplicationId', 
            'FileName', 'FolderPath', 'ResourceIdName', 'OSFamily', 'OSVersion', 
            'CountryCode', 'State', 'City'
        ]
    
        threat_categories = [
            'InitialAccess', 'Exfiltration', 'CommandAndControl', 'Execution', 
            'SuspiciousActivity', 'Impact', 'Collection', 'CredentialAccess', 
            'Persistence', 'Discovery', 'Malware', 'DefenseEvasion', 'Exploit', 
            'PrivilegeEscalation', 'LateralMovement', 'Ransomware', 
            'UnwantedSoftware', 'CredentialStealing'
        ]
    
        # Cast timestamp
        lf = lf.with_columns(
            pl.col("Timestamp").str.to_datetime(format="%Y-%m-%dT%H:%M:%S.%fZ", strict=False)
        )
    
    
        # Define base aggregations
        aggs = [
            pl.col("OrgId").first(),
            pl.col("IncidentGrade").first(),
            (pl.col("Timestamp").max() - pl.col("Timestamp").min()).dt.total_seconds().alias("incident_duration_seconds")
        ]
       
        # Add unique counts
        aggs.extend([
            pl.col(f).n_unique().alias(f"unique_{f.lower()}_count") for f in features_to_count
        ])
        
        # calculate velocity
        aggs.append(pl.len().alias("total_evidence_count"))
    
        aggs.extend([
            (pl.col('Category') == cat).any().cast(pl.Int32).alias(f"cat_{cat}") for cat in threat_categories
        ])
    
        aggs.extend([
                   pl.col('AlertTitle').drop_nulls().unique().str.join(" ").alias('text_AlertTitle'),
                   pl.col('FileName').drop_nulls().unique().str.join(" ").alias("text_FileName")
               ])
            
        # Execute Groupby
        print("Executing lazy query plan across the Query Point...")
        df_features = lf.group_by("IncidentId").agg(aggs)
        
        # Now we perform math on the aggregated columns to create behavioral signals
        df_features = df_features.with_columns([
            
            # 1. Velocity: How fast is this happening? 
            (pl.col("total_evidence_count") / (pl.col("incident_duration_seconds") + 1)).alias("evidence_per_second"),
            
            # 2. Lateral Movement: How many devices is a single account touching?
            (pl.col("unique_deviceid_count") / (pl.col("unique_accountname_count") + 1)).alias("devices_per_account"),
            
            # 3. Network Spread: How many IPs per device?
            (pl.col("unique_ipaddress_count") / (pl.col("unique_deviceid_count") + 1)).alias("ips_per_device"),
            
            # 4. Impossible Travel / Multinational Flag (1 if true, 0 if false)
            (pl.col("unique_countrycode_count") > 1).cast(pl.Int32).alias("is_multinational"),
            
            # 5. Instantaneous Flag: Did this entire incident happen in under 1 second?
            (pl.col("incident_duration_seconds") == 0).cast(pl.Int32).alias("is_instantaneous")
        ])

        df_collected = df_features.collect(streaming = True)
        alert_sparse = self.tfidf_alert.transform(df_collected['text_AlertTitle'].fill_null("").to_list())
        file_sparse = self.tfidf_file.transform(df_collected['text_FileName'].fill_null("").to_list())

        
        dense_cols = ['incident_duration_seconds','total_evidence_count','evidence_per_second','devices_per_account','ips_per_device','is_multinational','is_instantaneous']
        dense_cols.extend([f"unique_{f.lower()}_count" for f in features_to_count])
        dense_cols.extend([f"cat_{cat}" for cat in threat_categories])

        dense_matrix = df_collected.select(dense_cols).to_numpy()

        self.feature_names = dense_cols + [f'alert_{feat}' for feat in self.tfidf_alert.get_feature_names_out()] + [f'file_{feat}' for feat in self.tfidf_file.get_feature_names_out()]

        X_fused = sp.hstack([dense_matrix,alert_sparse,file_sparse]).tocsr()

        self.current_batch_ids = df_collected['IncidentId'].to_list()
        return X_fused
    
    def _extract_evidence(self,X_fused : sp.csr_matrix) -> list:
        print("Extracting SHAP evidence...")
        shap_values_all = self.explainer.shap_values(X_fused)

        # if isinstance(shap_values_all,list):
        #     shap_target = shap_values_all[2]
        # else:
        #     shap_target = shap_values_all
        # print(type(shap_values_all))
        # print(np.shape(shap_values_all))
        shap_target = shap_values_all[:, :, 2]

        X_dense = X_fused.toarray()
        batch_evidence = []

        for i in range(X_dense.shape[0]):
            incident_shap = shap_target[i]
            incident_actual = X_dense[i]

            valid_indices = np.where((incident_shap > 0) & (incident_actual > 0))[0]
            sorted_indices = valid_indices[np.argsort(-incident_shap[valid_indices])]
            top_indices = sorted_indices[:5]
            evidence_list = []
            for idx in top_indices:
                feature_name = self.feature_names[idx]
                actual_val = float(incident_actual[idx])
                impact = float(incident_shap[idx])

                evidence_list.append({
                    'feature' : feature_name,
                    'value' : actual_val,
                    'shap_impact' : round(impact,4) 
                })
            batch_evidence.append(evidence_list)

        return batch_evidence

    def triage_batch(self,raw_incidents) -> list:
        if raw_incidents is None:
            return []

        X_fused = self._preprocess(raw_incidents)
        print("Scoring incidents...")
        raw_probs = self.raw_xgb.predict_proba(X_fused)[:,2]
        calibrated_probs = self.calibrated_xgb.predict_proba(X_fused)[:,2]
        
        batch_evidence = self._extract_evidence(X_fused)

        ## Final Response Payload
        print("Loading the final payload ...")
        triage_queue = []
        for i in range(len(self.current_batch_ids)):
            triage_queue.append({
                "incident_id" : self.current_batch_ids[i],
                "threat_score": round(float(calibrated_probs[i]),4),
                "raw_score" : round(float(raw_probs[i]),5),
                "evidence" : batch_evidence[i]
            })

        triage_queue.sort(key=lambda x : (x['threat_score'],x['raw_score']), reverse=True)

        return triage_queue

if __name__ == "__main__":
    
    print("--- BOOTING ENGINE ---")
    engine = ThreatTriageEngine(model_dir="../../models")

    print("\n--- LOADING MOCK PAYLOAD ---")
    raw_df = pl.read_csv("../../data/01_raw/GUIDE_Test.csv")

    print(raw_df.schema)
    
    print(f"Loaded {raw_df.shape[0]} raw logs for processing.")

    print("\n--- EXECUTING TRIAGE PIPELINE ---")
    ranked_queue = engine.triage_batch(raw_df)
    
    print("\n--- TOP THREAT DETECTED ---")
    if ranked_queue:
        soc_analyst_choice = int(input("How many top suspicious evidences you want to lookup... : "))
        print(json.dumps(ranked_queue[ : soc_analyst_choice], indent=2))
    else:
        print("Queue is empty.")