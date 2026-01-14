#!/usr/bin/env python3
"""
Convert ampel.intoto.json to evidence.json format
"""
import json
import base64
from datetime import datetime

def convert_ampel_to_evidence(ampel_file, output_file):
    # Read the in-toto file
    with open(ampel_file, 'r') as f:
        ampel_data = json.load(f)
    
    # Extract and decode the payload
    payload_b64 = ampel_data['dsseEnvelope']['payload']
    payload = json.loads(base64.b64decode(payload_b64))
    
    predicate = payload.get('predicate', {})
    results = predicate.get('results', [])
    meta = predicate.get('meta', {})
    policy_set = predicate.get('policy_set', {})
    
    # Convert timestamp
    date_start = predicate.get('date_start', '')
    if date_start:
        try:
            dt = datetime.fromisoformat(date_start.replace('Z', '+00:00'))
            timestamp_ms = int(dt.timestamp() * 1000)
        except:
            timestamp_ms = 0
    else:
        timestamp_ms = 0
    
    # Determine status
    status = predicate.get('status', 'UNKNOWN').upper()
    status_id = 2 if status == 'FAIL' else 1 if status == 'PASS' else 0
    
    # Extract policy information
    policy_name = policy_set.get('id', 'Ampel Policy')
    frameworks = meta.get('frameworks', [])
    framework_name = frameworks[0].get('name', '') if frameworks else ''
    
    # Build policy data
    policy_data = {
        "name": policy_name,
        "description": f"Policy from {framework_name}" if framework_name else "Ampel Policy",
        "sources": []
    }
    
    # Extract policy sources from results
    for result in results:
        policy_id = result.get('policy', {}).get('id', '')
        if policy_id:
            policy_data["sources"].append({
                "name": policy_id,
                "policy": [],
                "ruleData": {},
                "config": {}
            })
    
    # Create evidence structure
    evidence = {
        "activity_id": 0,
        "activity_name": "",
        "category_name": "Application Activity",
        "category_uid": 6,
        "class_name": "Scan Activity",
        "class_uid": 6007,
        "cloud": {
            "provider": ""
        },
        "event_day": 0,
        "metadata": {
            "log_provider": "ampel",
            "product": {
                "name": "ampel",
                "vendor_name": "carabiner",
                "version": "v0.0.1"
            },
            "uid": f"ampel-{policy_name.replace(' ', '-')}",
            "version": "v0.0.1"
        },
        "num_files": 1,
        "observables": [
            {
                "name": "ampel.intoto.json",
                "type": "File Name",
                "type_id": 7
            }
        ],
        "osint": None,
        "scan": {
            "type_id": 0
        },
        "severity": "unknown",
        "severity_id": 0,
        "status": "failure" if status == "FAIL" else "success" if status == "PASS" else "unknown",
        "status_id": status_id,
        "time": timestamp_ms,
        "type_name": "",
        "type_uid": 60070,
        "policy": {
            "data": json.dumps(policy_data),
            "desc": policy_data["description"],
            "name": policy_name,
            "uid": policy_name.lower().replace(' ', '_')
        },
        "action": "observed",
        "action_id": 3
    }
    
    # Write output
    with open(output_file, 'w') as f:
        json.dump(evidence, f, indent=2)
    
    print(f"Successfully converted {ampel_file} to {output_file}")

if __name__ == "__main__":
    convert_ampel_to_evidence('ampel.intoto.json', 'evidence.json')

