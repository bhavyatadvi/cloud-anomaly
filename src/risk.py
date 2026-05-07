def calculate_risk(df, high_risk_events):
    # More conservative risk scoring
    risk_score = (
        df['ml_flag'] * 2 +  # Reduced from 3 to 2
        df['is_failed'] * 1 +
        df['is_root'] * 1 +  # Increased from 0.5 to 1 for root importance
        df['eventName_raw'].isin(high_risk_events).astype(int) * 4  # Increased high-risk weight
    )

    # Night activity - reduced weight
    risk_score += df['is_night'] * 0.3

    # Root + high-risk combination - higher penalty
    root_high_risk = (df['is_root'] == 1) & (df['eventName_raw'].isin(high_risk_events))
    risk_score += root_high_risk.astype(int) * 2

    # Failed root operations - higher penalty
    failed_root = (df['is_failed'] == 1) & (df['is_root'] == 1)
    risk_score += failed_root.astype(int) * 1.5

    # ML anomaly + root - higher penalty
    anomaly_root = (df['ml_flag'] == 1) & (df['is_root'] == 1)
    risk_score += anomaly_root.astype(int) * 1.5

    df['risk_score'] = risk_score

    # Higher thresholds for risk levels - more conservative
    df['risk_level'] = df['risk_score'].apply(lambda x:
        'CRITICAL' if x >= 8 else
        'HIGH' if x >= 5 else
        'MEDIUM' if x >= 3 else
        'LOW')

    return df

    # Reduce normal behavior
    normal = (
        (df['is_root'] == 0) &
        (df['is_failed'] == 0) &
        (df['is_night'] == 0) &
        (~df['eventName_raw'].isin(high_risk_events))
    )
    risk_score -= normal.astype(int) * 1

    df['risk_score'] = risk_score

    df['risk_level'] = df['risk_score'].apply(
        lambda x: 'CRITICAL' if x >= 6 else (
            'HIGH' if x >= 3 else (
                'MEDIUM' if x >= 1.5 else 'LOW'
            )
        )
    )

    return df

