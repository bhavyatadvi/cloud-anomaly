import pandas as pd
from src.preprocess import load_data
from src.feature_engineering import feature_engineering
from src.encode import encode_features
from src.model import train_model, detect_anomalies, add_anomaly_flags
from src.risk import calculate_risk
from src.explain import generate_explanation

def main_pipeline():
    # Define risk events
    high_risk_events = [
        'DeleteBucket', 'PutBucketPolicy', 'CreateUser', 'AttachUserPolicy',
        'CreateAccessKey', 'StopLogging', 'StartLogging'
    ]
    medium_risk_events = [
        'ListBuckets', 'ListTopics', 'GetObject', 'DescribeInstances'
    ]

    # 1. Data Loading
    df = load_data('data/cleaned_data.csv')

    # 2. Feature Engineering
    df = feature_engineering(df)

    # 3. Encoding
    df = encode_features(df)

    # 4. Model Training
    features = ['eventName', 'eventSource', 'sourceIPAddress', 'awsRegion', 'userAgent', 'hour', 'is_night', 'is_failed', 'is_root']
    X = df[features]
    model = train_model(X)

    # 5. Anomaly Detection
    predictions = detect_anomalies(model, X)
    df = add_anomaly_flags(df, predictions)

    # 6. Risk Scoring and Classification
    df = calculate_risk(df, high_risk_events)

    # 7. Explainability
    df['reason'] = df.apply(lambda row: generate_explanation(row, high_risk_events, medium_risk_events), axis=1)

    # 8. Output
    # 8. Output (Improved Filtering)

    suspicious_df = df[
      (df['risk_score'] >= 5) &
    (
        (df['ml_flag'] == 1) | 
        (df['is_root'] == 1)
      ) &
      (df['userIdentitytype'] != 'AWSAccount')
    ][
      ['eventTime', 'eventName_raw', 'sourceIPAddress',
     'userIdentityuserName', 'userIdentitytype',
     'risk_score', 'reason']
    ]

# Remove duplicates
    suspicious_df = suspicious_df.drop_duplicates(
      subset=['eventName_raw', 'userIdentityuserName', 'sourceIPAddress']
    )
# Save output
    suspicious_df.to_csv('suspicious_output.csv', index=False)

    return suspicious_df

if __name__ == "__main__":
    suspicious_df = main_pipeline()
    print("Pipeline completed. Suspicious activities saved to suspicious_output.csv")
    print(f"Number of HIGH risk events: {len(suspicious_df)}")