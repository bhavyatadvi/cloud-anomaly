import pandas as pd

def load_data(path):
    return pd.read_csv(path)

def clean(df):
    df = df.drop_duplicates()
    return df