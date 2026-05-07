from sklearn.ensemble import IsolationForest

def train_model(X):
    model = IsolationForest(contamination=0.0005, random_state=42)  # Reduced from 0.01 to 0.0005 (0.05%)
    model.fit(X)
    return model

def detect_anomalies(model, X):
    predictions = model.predict(X)
    return predictions

def add_anomaly_flags(df, predictions):
    df['anomaly'] = predictions
    df['ml_flag'] = (predictions == -1).astype(int)
    return df

def add_anomaly_flags(df, predictions):
    df['anomaly'] = predictions
    df['ml_flag'] = (predictions == -1).astype(int)
    return df

