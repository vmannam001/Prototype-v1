import csv
import json
import sys
from collections import defaultdict
from policy_evaluator import evaluate_request

def run_simulation(log_file, old_policy_path, new_policy_path):
    """
    Compares the outcomes of old and new policies against access logs
    and generates an impact report.
    """
    try:
        with open(old_policy_path, 'r') as f:
            old_policy = json.load(f)
        with open(new_policy_path, 'r') as f:
            new_policy = json.load(f)
    except FileNotFoundError as e:
        print(f"Error loading policy file: {e}")
        sys.exit(1)

    affected_users = defaultdict(list)

    with open(log_file, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # This dictionary contains all the details for a single access request.
            request_params = {
                'role': row['role'],
                'department': row['department'],
                'resource': row['resource'],
                'action': row['action']
            }

            # We now pass the entire dictionary directly to the evaluator.
            old_dec, old_reason = evaluate_request(old_policy, request_params)
            new_dec, new_reason = evaluate_request(new_policy, request_params)

            if new_dec != old_dec:
                why = new_reason if new_dec == 'denied' else "Permitted by new policy rule."
                affected_users[row['user_id']].append({
                    'resource': row['resource'],
                    'action': row['action'],
                    'change': f"{old_dec} -> {new_dec}",
                    'why': why
                })
    
    write_report(affected_users)

def write_report(affected_users):
    """Writes the simulation results to simulation_result.txt."""
    with open('simulation_result.txt', 'w') as out_f:
        out_f.write("## 📜 Policy Impact Analysis\n\n")
        
        denied_users = {k: [c for c in v if '-> denied' in c['change']] for k, v in affected_users.items() if any('-> denied' in c['change'] for c in v)}
        if denied_users:
            out_f.write("### ❌ Users Who Will Lose Access\n")
            for user_id, changes in denied_users.items():
                out_f.write(f"- **User `{user_id}`**:\n")
                for change in changes:
                    out_f.write(f"  - For `{change['action']}` on `{change['resource']}`, will be **denied**. *Reason: {change['why']}*\n")
        
        permitted_users = {k: [c for c in v if '-> permitted' in c['change']] for k, v in affected_users.items() if any('-> permitted' in c['change'] for c in v)}
        if permitted_users:
            out_f.write("\n### ✅ Users Who Will Gain Access\n")
            for user_id, changes in permitted_users.items():
                out_f.write(f"- **User `{user_id}`**:\n")
                for change in changes:
                    out_f.write(f"  - For `{change['action']}` on `{change['resource']}`, will now be **permitted**.\n")

        if not denied_users and not permitted_users:
            out_f.write("✅ **No access changes detected for any user based on the historical logs.**\n")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python policy_simulation.py <path_to_old_policy.json> <path_to_new_policy.json>")
        sys.exit(1)
    
    old_file_path = sys.argv[1]
    new_file_path = sys.argv[2]
    
    run_simulation('access_logs.csv', old_file_path, new_file_path)