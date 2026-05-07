from sklearn.preprocessing import LabelEncoder

def encode_features(df):
    cols = ['eventName', 'eventSource', 'sourceIPAddress', 'awsRegion', 'userAgent']

    for col in cols:
        df[col] = LabelEncoder().fit_transform(df[col])

    return df