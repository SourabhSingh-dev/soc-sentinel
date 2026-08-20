import polars as pl
import pandas as pd
import numpy as np
import scipy.sparse as sp
import joblib
import argparse
import os


def space_tokenizer(x):
    return str(x).split()

def load_artifacts():
    print("Loading inference artifacts...")
    try :
        model = joblib.load("../../models/xgb_fused_model.joblib")
        tfidf_alert = joblib.load("../../models/tfidf_alert_vectorizer.joblib")
        tfidf_file = joblib.load("../../models/tfidf_file_vectorizer.joblib")
        return model,tfidf_alert,tfidf_file
    except FileNotFoundError as e:
        print(f"FATAL ERROR: Could not find model artifact. {e}")
        exit(1) 

def engineer_features(raw_csv_path):
    print(f"Ingesting raw telemetry from {raw_csv_path}...")

    lf = pl.read_csv(raw_csv_path)

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
    lf = pl.scan_csv(raw_csv_path, ignore_errors=True)

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
    print("Executing lazy query plan across the dataset...")
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

    return df_features.collect(streaming=True).to_pandas()

def score_threats(df,model,tfidf_alert,tfidf_file,threshold=0.40):
    print("Vectorizing text payloads...")

    text_alert = df['text_AlertTitle'].fillna("")
    text_file = df['text_FileName'].fillna("")

    X_base = df.drop(columns=['IncidentId','OrgId','IncidentGrade','text_AlertTitle','text_FileName','target'],errors='ignore')

    alert_tfidf = tfidf_alert.transform(text_alert)
    file_tfidf = tfidf_file.transform(text_file)

    print("Fusing feature matrix...")
    X_fused = sp.hstack([sp.csr_matrix(X_base),alert_tfidf,file_tfidf])

    print("Executing model inference...")

    y_prob = model.predict_proba(X_fused)
    tp_prob = y_prob[:,2]

    print(f"Applying custom SOC threshold: {threshold}")

    final_predictions = np.where(
        tp_prob >= threshold,
        2,
        np.argmax(y_prob[:,:2],axis=1)
    )

    df['Predicted_Threat_Level'] = final_predictions
    df['True_Positive_Probability'] = tp_prob

    return df[['IncidentId','Predicted_Threat_Level','True_Positive_Probability']]

def main():
    parser = argparse.ArgumentParser(description='Run batch inference on raw SOC telemetry.')
    parser.add_argument("--input",type=str,required=True,help="Path to raw input CSV file")
    parser.add_argument("--output",type=str,default="../../data/04_predictions/scored_alerts.csv",help="Path to save predictions")
    args = parser.parse_args()

    model,tfidf_alert,tfidf_file = load_artifacts()

    df_features = engineer_features(args.input)

    if df_features is None:
        print("FATAL ERROR: There is an issue with engineer_features().")
        exit(1)

    df_scored = score_threats(df_features,model,tfidf_alert,tfidf_file,threshold=0.40)

    os.makedirs(os.path.dirname(args.output),exist_ok=True)
    df_scored.to_csv(args.output,index=False)

    print(f"\nSUCCESS: Scored {len(df_scored)} incidents.")
    print(f"Output saved to: {args.output}")

if __name__ == '__main__':
    main()