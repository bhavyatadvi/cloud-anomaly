def generate_explanation(row, high_risk_events, medium_risk_events):
    # Priority-based single reason selection

    # Critical threats - highest priority
    if row['eventName_raw'] in ['DeleteBucket', 'PutBucketPolicy'] and row['is_root'] == 1:
        return "Potential data destruction: Root user modifying bucket security policies"
    elif row['eventName_raw'] in ['CreateUser', 'AttachUserPolicy', 'CreateAccessKey'] and row['is_root'] == 1:
        return "Privilege escalation: Root creating new IAM users and access keys"
    elif row['eventName_raw'] in ['StopLogging', 'StartLogging'] and row['is_root'] == 1:
        return "Audit evasion: Root tampering with CloudTrail logging configuration"
    elif row['eventName_raw'] in high_risk_events and row['userIdentitytype'] == 'IAMUser':
        return "IAM user performing sensitive administrative action"
    # High-risk combinations
    elif row['eventName_raw'] in high_risk_events and row['is_root'] == 1 and row['is_failed'] == 1:
        return "Failed high-risk operation by root account - potential compromise"
    elif row['eventName_raw'] in high_risk_events and row['is_root'] == 1:
        return "High-risk administrative action performed with root privileges"
    elif row['eventName_raw'] in high_risk_events:
        return "High-risk API operation detected"
    
    
    # Root account suspicious patterns
    elif row['is_root'] == 1 and row['is_failed'] == 1 and row['ml_flag'] == 1 and row['is_night'] == 1:
        return "Root account compromise: Failed operations with anomalies during off-hours"
    elif row['is_root'] == 1 and row['is_failed'] == 1 and row['ml_flag'] == 1:
        return "Root account showing compromised behavior patterns"
    elif row['is_root'] == 1 and row['ml_flag'] == 1 and row['is_night'] == 1:
        return "Unusual root activity detected during off-hours"
    elif row['is_root'] == 1 and row['ml_flag'] == 1:
        return "Anomalous root account behavior detected"
    elif row['is_root'] == 1 and row['is_failed'] == 1:
        return "Root account operation failed - investigate access"
    elif row['is_root'] == 1 and row['is_night'] == 1:
        return "Root account activity during unusual hours"
    elif row['is_root'] == 1:
        return "Root account privilege usage detected"

    # Reconnaissance activities
    elif row['eventName_raw'] in medium_risk_events and row['is_root'] == 1:
        return "Reconnaissance: Root user scanning cloud resources"
    elif row['eventName_raw'] in medium_risk_events:
        return "Resource enumeration activity detected"

    # Failure patterns
    elif row['is_failed'] == 1 and row['ml_flag'] == 1 and row['is_night'] == 1:
        return "Suspicious failed operation with anomalies during off-hours"
    elif row['is_failed'] == 1 and row['ml_flag'] == 1:
        return "Failed operation combined with anomalous behavior"
    elif row['is_failed'] == 1 and row['is_night'] == 1:
        return "Operation failed during off-hours - possible attack"
    elif row['is_failed'] == 1:
        return "API operation failed - check for misconfiguration or attack"

    # Anomaly patterns
    elif row['ml_flag'] == 1 and row['is_night'] == 1:
        return "Unusual behavior detected during off-hours"
    elif row['ml_flag'] == 1:
        return "Anomalous activity pattern detected"

    # Time-based patterns
    elif row['is_night'] == 1:
        return "Activity occurred during off-hours (00:00-06:00)"

    # Default fallback
    else:
        return "Activity flagged for security review"