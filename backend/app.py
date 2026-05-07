from flask import Flask, jsonify
import pandas as pd
from flask_cors import CORS
from collections import Counter

app = Flask(__name__)
CORS(app)

def load_suspicious_data():
    """Load and return the suspicious output data."""
    df = pd.read_csv('../suspicious_output.csv')
    df['eventTime'] = pd.to_datetime(df['eventTime'])
    return df

@app.route('/api/suspicious', methods=['GET'])
def get_suspicious():
    df = load_suspicious_data()
    data = df.to_dict(orient='records')
    # Convert timestamps to strings for JSON
    for record in data:
        record['eventTime'] = str(record['eventTime'])
    return jsonify(data)

@app.route('/api/analytics', methods=['GET'])
def get_analytics():
    """Provide comprehensive analytics for the dashboard."""
    df = load_suspicious_data()
    
    # --- Risk Score Distribution ---
    risk_distribution = []
    bins = [(5, 5.9, '5.0-5.9'), (6, 6.9, '6.0-6.9'), (7, 7.9, '7.0-7.9'), (8, 8.9, '8.0-8.9'), (9, 10, '9.0-10.0')]
    for low, high, label in bins:
        count = len(df[(df['risk_score'] >= low) & (df['risk_score'] <= high)])
        risk_distribution.append({'range': label, 'count': count})
    
    # --- Events by Type (Pie chart) ---
    event_counts = df['eventName_raw'].value_counts().to_dict()
    events_by_type = [{'name': k, 'value': v} for k, v in event_counts.items()]
    
    # --- Timeline: Events over time ---
    df['date'] = df['eventTime'].dt.strftime('%Y-%m-%d')
    timeline_counts = df.groupby('date').agg(
        count=('eventName_raw', 'size'),
        avg_risk=('risk_score', 'mean')
    ).reset_index()
    timeline = timeline_counts.to_dict(orient='records')
    for item in timeline:
        item['avg_risk'] = round(item['avg_risk'], 2)
    
    # --- User Analysis ---
    user_activity = df.groupby('userIdentityuserName').agg(
        total_events=('eventName_raw', 'size'),
        avg_risk=('risk_score', 'mean'),
        max_risk=('risk_score', 'max')
    ).reset_index()
    user_activity.columns = ['user', 'total_events', 'avg_risk', 'max_risk']
    user_analysis = user_activity.to_dict(orient='records')
    for item in user_analysis:
        item['avg_risk'] = round(item['avg_risk'], 2)
        item['max_risk'] = round(item['max_risk'], 2)
    
    # --- IP Address Analysis ---
    ip_counts = df['sourceIPAddress'].value_counts().to_dict()
    ip_analysis = [{'ip': k, 'count': v} for k, v in ip_counts.items()]
    
    # --- Threat Categories from reason field ---
    threat_categories = {}
    for reason in df['reason']:
        if 'data destruction' in reason.lower():
            cat = 'Data Destruction'
        elif 'privilege escalation' in reason.lower():
            cat = 'Privilege Escalation'
        elif 'audit evasion' in reason.lower():
            cat = 'Audit Evasion'
        elif 'root account compromise' in reason.lower() or 'compromise' in reason.lower():
            cat = 'Account Compromise'
        elif 'reconnaissance' in reason.lower():
            cat = 'Reconnaissance'
        else:
            cat = 'Other'
        threat_categories[cat] = threat_categories.get(cat, 0) + 1
    
    threat_breakdown = [{'category': k, 'count': v} for k, v in threat_categories.items()]
    
    # --- Summary Stats ---
    summary = {
        'total_suspicious': len(df),
        'unique_users': df['userIdentityuserName'].nunique(),
        'unique_ips': df['sourceIPAddress'].nunique(),
        'avg_risk_score': round(df['risk_score'].mean(), 2),
        'max_risk_score': round(df['risk_score'].max(), 2),
        'critical_events': len(df[df['risk_score'] >= 8]),
        'high_events': len(df[(df['risk_score'] >= 5) & (df['risk_score'] < 8)]),
        'unique_event_types': df['eventName_raw'].nunique(),
        'date_range_start': str(df['eventTime'].min()),
        'date_range_end': str(df['eventTime'].max()),
    }
    
    # --- Hourly Activity Heatmap ---
    df['hour'] = df['eventTime'].dt.hour
    hourly_activity = df.groupby('hour').size().reindex(range(24), fill_value=0)
    hourly = [{'hour': h, 'count': int(c)} for h, c in hourly_activity.items()]
    
    return jsonify({
        'summary': summary,
        'risk_distribution': risk_distribution,
        'events_by_type': events_by_type,
        'timeline': timeline,
        'user_analysis': user_analysis,
        'ip_analysis': ip_analysis,
        'threat_breakdown': threat_breakdown,
        'hourly_activity': hourly,
    })

if __name__ == '__main__':
    app.run(debug=True)