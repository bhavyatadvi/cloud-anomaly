import pandas as pd

def feature_engineering(df):
    # Convert eventTime to datetime
    df['eventTime'] = pd.to_datetime(df['eventTime'])

    # Extract hour
    df['hour'] = df['eventTime'].dt.hour

    # Create is_night: 1 if between 00:00-06:00
    df['is_night'] = ((df['hour'] >= 0) & (df['hour'] < 6)).astype(int)

    # Create is_failed: 1 if errorCode is not "NoError"
    df['is_failed'] = (df['errorCode'] != "NoError").astype(int)

    # Create is_root: 1 if userIdentitytype is "Root"
    df['is_root'] = (df['userIdentitytype'] == "Root").astype(int)

    # Preserve original eventName if not already present
    if 'eventName_raw' not in df.columns:
        df['eventName_raw'] = df['eventName']

    return df