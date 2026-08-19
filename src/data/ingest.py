import polars as pl

def build_incident_features(raw_csv_path: str) -> pl.DataFrame:
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

    return df_features.collect(streaming=True)

if __name__ == "__main__":
    file_path = "../../data/01_raw/GUIDE_Train.csv"
    final_df = build_incident_features(file_path)
    
    print(f"Final dataset shape: {final_df.shape}")
    final_df.write_parquet("../../data/03_processed/version_two_engineered_features_train.parquet")
    print("Saved to data/03_processed/version_two_engineered_features_train.parquet")