#!/usr/bin/env python3
import os
import json
import csv
import re
from pathlib import Path
import sys
from collections import Counter, defaultdict
import datetime

# paths
data_dir = Path("processed")
reports_dir = Path("reports")
actions_inventory_json = data_dir / "actions_inventory.json"
actions_summary_json = data_dir / "actions_summary.json"
output_html = reports_dir / "github_actions_security_report.html"
output_markdown = reports_dir / "github_actions_security_report.md"

os.makedirs(reports_dir, exist_ok=True)

# risk classification patterns
HIGH_RISK_PATTERNS = [
    r"docker://",  
    r"run:",       
    r"setup-",     
    r"checkout@",  
    r"upload-",    
    r"download-",  
    r"deploy-",    
    r"aws-",       
    r"gcp-",       
    r"azure-",     
    r"terraform-", 
    r"kubernetes-",
    r"docker",     
    r"ssh-",       
]

# production indicators
PRODUCTION_INDICATORS = [
    r'prod',
    r'release',
    r'deploy',
    r'publish',
    r'main',
    r'master',
    r'live',
    r'kubesealer',
    r'docker-publish',
    r'delivery'
]

def load_inventory_data():
    try:
        with open(actions_inventory_json, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"error: {actions_inventory_json} not found. run action_extractor.py first!")
        sys.exit(1)

def load_summary_data():
    try:
        with open(actions_summary_json, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"error: {actions_summary_json} not found. run action_extractor.py first!")
        sys.exit(1)

def calculate_risk_score(action):
    base_score = 0
    
    # npinned actions are higher risk
    if not action["is_pinned"]:
        base_score += 30
    
    # actions requiring secrets are higher risk
    if action["has_secrets"]:
        base_score += 25
    
    # check for high-risk patterns
    for pattern in HIGH_RISK_PATTERNS:
        if re.search(pattern, action["action_name"], re.IGNORECASE) or re.search(pattern, action["full_reference"], re.IGNORECASE):
            base_score += 15
            break
    
    # third-party vs. github-owned actions
    if action["is_third_party"]:
        base_score += 20
    
    # actions in production workflows might be higher risk
    for indicator in PRODUCTION_INDICATORS:
        if re.search(indicator, action["workflow_file"], re.IGNORECASE) or re.search(indicator, action["workflow_path"], re.IGNORECASE):
            base_score += 10
            break
    
    return min(base_score, 100)  # Cap at 100

def determine_privileged(action):
    privileged_patterns = {
        "docker": "container manipulation privileges",
        "kube": "kubernetes api access",
        "admin": "administrative access",
        "root": "root/elevated permissions",
        "privileged": "explicitly marked as privileged",
        "sudo": "sudo/superuser execution"
    }
    
    matched_reasons = []
    for pattern, reason in privileged_patterns.items():
        if re.search(pattern, action["action_name"], re.IGNORECASE) or re.search(pattern, str(action["with_params"]), re.IGNORECASE):
            matched_reasons.append(f"{reason} ({pattern})")
    
    if matched_reasons:
        action["privileged_reasons"] = matched_reasons
        return True
    
    return False

def determine_file_system_access(action):
    fs_access_patterns = {
        "checkout": "source code access",
        "upload": "file upload capabilities",
        "download": "file download capabilities",
        "artifact": "artifact manipulation",
        "cache": "cache access",
        "file": "file operations",
        "path": "path manipulation",
        "dir": "directory operations",
        "directory": "directory operations"
    }
    
    matched_reasons = []
    for pattern, reason in fs_access_patterns.items():
        if re.search(pattern, action["action_name"], re.IGNORECASE) or re.search(pattern, str(action["with_params"]), re.IGNORECASE):
            matched_reasons.append(f"{reason} ({pattern})")
    
    if matched_reasons:
        action["fs_access_reasons"] = matched_reasons
        return True
    
    return False

def determine_network_access(action):
    network_patterns = {
        "http": "http requests",
        "curl": "curl commands",
        "wget": "wget downloads",
        "api": "api access",
        "request": "network requests",
        "fetch": "data fetching",
        "download": "download capability",
        "deploy": "deployment (potentially remote)",
        "publish": "publishing (potentially remote)"
    }
    
    matched_reasons = []
    for pattern, reason in network_patterns.items():
        if re.search(pattern, action["action_name"], re.IGNORECASE) or re.search(pattern, str(action["with_params"]), re.IGNORECASE):
            matched_reasons.append(f"{reason} ({pattern})")
    
    if matched_reasons:
        action["network_access_reasons"] = matched_reasons
        return True
    
    return False

def determine_deprecated(action):
    deprecated_patterns = [
        r"deprecated",
        r"v[0-9]+.*",
        r"legacy"
    ]
    
    for pattern in deprecated_patterns:
        if re.search(pattern, action["action_name"], re.IGNORECASE):
            return True
    
    return False

def identify_production_workflows(actions_data):
    for action in actions_data:
        # check if workflow name or path suggests production
        is_prod = any(re.search(pattern, action["workflow_file"], re.IGNORECASE) or 
                      re.search(pattern, action["workflow_path"], re.IGNORECASE)
                      for pattern in PRODUCTION_INDICATORS)
        
        # also check job name if available
        if "job_name" in action and action["job_name"]:
            is_prod = is_prod or any(re.search(pattern, action["job_name"], re.IGNORECASE) 
                                    for pattern in PRODUCTION_INDICATORS)
        
        # store the result and the matched pattern if any
        if is_prod:
            matched_patterns = []
            for pattern in PRODUCTION_INDICATORS:
                if (re.search(pattern, action["workflow_file"], re.IGNORECASE) or 
                    re.search(pattern, action["workflow_path"], re.IGNORECASE) or
                    ("job_name" in action and action["job_name"] and 
                     re.search(pattern, action["job_name"], re.IGNORECASE))):
                    matched_patterns.append(pattern)
            
            action["production_workflow"] = True
            action["production_indicators"] = list(set(matched_patterns))
        else:
            action["production_workflow"] = False
            action["production_indicators"] = []
    
    return actions_data

def classify_actions(actions_data):
    for action in actions_data:
        # calculate risk score
        action["risk_score"] = calculate_risk_score(action)
        
        # assign risk level
        if action["risk_score"] >= 70:
            action["risk_level"] = "High"
        elif action["risk_score"] >= 40:
            action["risk_level"] = "Medium"
        else:
            action["risk_level"] = "Low"
        
        # additional classifications
        action["privileged"] = determine_privileged(action)
        action["file_system_access"] = determine_file_system_access(action)
        action["network_access"] = determine_network_access(action)
        action["deprecated"] = determine_deprecated(action)
    
    # identify production workflows
    actions_data = identify_production_workflows(actions_data)
    
    return actions_data

def generate_statistics(actions_data):
    stats = {
        "total_actions": len(actions_data),
        "unique_actions": len(set(a["action_name"] for a in actions_data)),
        "pinned_actions": sum(1 for a in actions_data if a["is_pinned"]),
        "unpinned_actions": sum(1 for a in actions_data if not a["is_pinned"]),
        "actions_with_secrets": sum(1 for a in actions_data if a["has_secrets"]),
        "privileged_actions": sum(1 for a in actions_data if a.get("privileged", False)),
        "file_system_access_actions": sum(1 for a in actions_data if a.get("file_system_access", False)),
        "network_access_actions": sum(1 for a in actions_data if a.get("network_access", False)),
        "deprecated_actions": sum(1 for a in actions_data if a.get("deprecated", False)),
        "risk_distribution": {
            "high": sum(1 for a in actions_data if a["risk_level"] == "High"),
            "medium": sum(1 for a in actions_data if a["risk_level"] == "Medium"),
            "low": sum(1 for a in actions_data if a["risk_level"] == "Low")
        },
        "repositories": len(set(a["repository"] for a in actions_data)),
        "action_usage_count": Counter([a["action_name"] for a in actions_data]),
        "top_actions": []
    }
    
    # production workflow statistics
    production_actions = [a for a in actions_data if a.get("production_workflow", False)]
    stats["production_workflow_actions"] = len(production_actions)
    stats["production_high_risk"] = sum(1 for a in production_actions if a["risk_level"] == "High")
    stats["production_unpinned"] = sum(1 for a in production_actions if not a["is_pinned"])
    stats["production_with_secrets"] = sum(1 for a in production_actions if a["has_secrets"])
    
    # calculate top actions
    stats["top_actions"] = stats["action_usage_count"].most_common(20)
    
    # calculate risk by repository
    repo_risk = defaultdict(list)
    for action in actions_data:
        repo_risk[action["repository"]].append(action["risk_score"])
    
    stats["repository_risk"] = {
        repo: sum(scores) / len(scores) for repo, scores in repo_risk.items()
    }
    
    # identify top high-risk repositories
    stats["high_risk_repositories"] = sorted(
        [(repo, avg_score) for repo, avg_score in stats["repository_risk"].items()],
        key=lambda x: x[1],
        reverse=True
    )[:10]
    
    return stats

def generate_html_report(actions_data, stats, summary_data):
    # basic css styling
    css = """
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; color: #333; }
        h1, h2, h3 { color: #2c3e50; }
        .summary { background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .stats { display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 30px; }
        .stat-box { flex: 1; min-width: 200px; background-color: #fff; box-shadow: 0 2px 5px rgba(0,0,0,0.1); padding: 15px; border-radius: 5px; }
        .stat-value { font-size: 24px; font-weight: bold; margin-bottom: 5px; }
        .stat-label { font-size: 14px; color: #666; }
        .highlight-box { border-left: 4px solid #dc3545; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        tr:hover { background-color: #f5f5f5; }
        .high { background-color: #ffdddd; }
        .medium { background-color: #ffffcc; }
        .low { background-color: #ddffdd; }
        .risk-badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
            color: white;
        }
        .risk-high { background-color: #dc3545; }
        .risk-medium { background-color: #ffc107; color: #333; }
        .risk-low { background-color: #28a745; }
        .timestamp { color: #666; font-size: 12px; margin-top: 40px; }
        .recommendation { background-color: #e3f2fd; padding: 15px; border-left: 4px solid #2196f3; margin: 20px 0; }
        .recommendation h3 { margin-top: 0; color: #0d47a1; }
        
        /* Tabs styling */
        .tab {
            overflow: hidden;
            border: 1px solid #ccc;
            background-color: #f1f1f1;
            border-radius: 5px 5px 0 0;
        }
        .tab button {
            background-color: inherit;
            float: left;
            border: none;
            outline: none;
            cursor: pointer;
            padding: 14px 16px;
            transition: 0.3s;
            font-size: 16px;
        }
        .tab button:hover { background-color: #ddd; }
        .tab button.active { background-color: #007bff; color: white; }
        .tabcontent {
            display: none;
            padding: 6px 12px;
            border: 1px solid #ccc;
            border-top: none;
            border-radius: 0 0 5px 5px;
            animation: fadeEffect 1s;
        }
        @keyframes fadeEffect {
            from {opacity: 0;}
            to {opacity: 1;}
        }
    </style>
    
    <script>
        function openTab(evt, tabName) {
            var i, tabcontent, tablinks;
            tabcontent = document.getElementsByClassName("tabcontent");
            for (i = 0; i < tabcontent.length; i++) {
                tabcontent[i].style.display = "none";
            }
            tablinks = document.getElementsByClassName("tablinks");
            for (i = 0; i < tablinks.length; i++) {
                tablinks[i].className = tablinks[i].className.replace(" active", "");
            }
            document.getElementById(tabName).style.display = "block";
            evt.currentTarget.className += " active";
        }
        
        // Set the default tab to open when the page loads
        document.addEventListener('DOMContentLoaded', function() {
            document.getElementsByClassName('tablinks')[0].click();
        });
    </script>
    """
    
    # HTML content
    html = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>GitHub Actions Security Assessment Report</title>
        {css}
    </head>
    <body>
        <h1>GitHub Actions Security Assessment Report</h1>
        <p class="timestamp">Generated on {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        
        <div class="summary">
            <h2>Executive Summary</h2>
            <p>This report provides a comprehensive security assessment of GitHub Actions usage across {stats["repositories"]} repositories. 
            A total of {stats["total_actions"]} action references were analyzed, representing {stats["unique_actions"]} unique actions.</p>
            <p>Key findings:</p>
            <ul>
                <li><strong>{stats["risk_distribution"]["high"]}</strong> high-risk action references identified ({stats["risk_distribution"]["high"]/stats["total_actions"]*100:.1f}% of total)</li>
                <li><strong>{stats["unpinned_actions"]}</strong> unpinned action references ({stats["unpinned_actions"]/stats["total_actions"]*100:.1f}% of total)</li>
                <li><strong>{stats["actions_with_secrets"]}</strong> actions using secrets ({stats["actions_with_secrets"]/stats["total_actions"]*100:.1f}% of total)</li>
                <li><strong>{stats["production_workflow_actions"]}</strong> actions in production workflows ({stats["production_workflow_actions"]/stats["total_actions"]*100:.1f}% of total)</li>
                <li><strong>{stats["production_high_risk"]}</strong> high-risk actions in production workflows</li>
            </ul>
        </div>
        
        <h2>Risk Overview</h2>
        <div class="stats">
            <div class="stat-box">
                <div class="stat-value">{stats["total_actions"]}</div>
                <div class="stat-label">Total Action References</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{stats["unique_actions"]}</div>
                <div class="stat-label">Unique Actions</div>
            </div>
            <div class="stat-box highlight-box">
                <div class="stat-value">{stats["risk_distribution"]["high"]}</div>
                <div class="stat-label">High Risk</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{stats["risk_distribution"]["medium"]}</div>
                <div class="stat-label">Medium Risk</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{stats["risk_distribution"]["low"]}</div>
                <div class="stat-label">Low Risk</div>
            </div>
        </div>
        
        <h2>Production Environment Status</h2>
        <div class="stats">
            <div class="stat-box highlight-box">
                <div class="stat-value">{stats["production_workflow_actions"]}</div>
                <div class="stat-label">Production Workflow Actions</div>
            </div>
            <div class="stat-box highlight-box">
                <div class="stat-value">{stats["production_high_risk"]}</div>
                <div class="stat-label">High Risk in Production</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{stats["production_unpinned"]}</div>
                <div class="stat-label">Unpinned in Production</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{stats["production_with_secrets"]}</div>
                <div class="stat-label">Using Secrets in Production</div>
            </div>
        </div>
        
        <h2>Action Security Metrics</h2>
        <div class="stats">
            <div class="stat-box">
                <div class="stat-value">{stats["pinned_actions"]}</div>
                <div class="stat-label">Pinned Actions</div>
            </div>
            <div class="stat-box highlight-box">
                <div class="stat-value">{stats["unpinned_actions"]}</div>
                <div class="stat-label">Unpinned Actions</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{stats["actions_with_secrets"]}</div>
                <div class="stat-label">Using Secrets</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{stats["privileged_actions"]}</div>
                <div class="stat-label">Potentially Privileged</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{stats["file_system_access_actions"]}</div>
                <div class="stat-label">File System Access</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{stats["network_access_actions"]}</div>
                <div class="stat-label">Network Access</div>
            </div>
        </div>
        
        <h2>Top 10 Repositories by Risk</h2>
        <table>
            <tr>
                <th>Repository</th>
                <th>Risk Score</th>
                <th>Action Count</th>
            </tr>
    """
    
    # add repository risk data
    repo_action_count = Counter([a["repository"] for a in actions_data])
    for repo, risk_score in stats["high_risk_repositories"]:
        risk_class = "high" if risk_score >= 60 else "medium" if risk_score >= 40 else "low"
        html += f"""
            <tr class="{risk_class}">
                <td>{repo}</td>
                <td>{risk_score:.1f}</td>
                <td>{repo_action_count[repo]}</td>
            </tr>
        """
    
    html += """
        </table>
        
        <h2>Top 20 Most Used Actions</h2>
        <table>
            <tr>
                <th>Action</th>
                <th>Usage Count</th>
                <th>Pinned Ratio</th>
                <th>Average Risk</th>
            </tr>
    """
    
    # add top actions
    for action_name, count in stats["top_actions"]:
        # calculate pinned ratio for this action
        action_instances = [a for a in actions_data if a["action_name"] == action_name]
        pinned_count = sum(1 for a in action_instances if a["is_pinned"])
        pinned_ratio = pinned_count / count if count > 0 else 0
        
        # calculate average risk score
        avg_risk = sum(a["risk_score"] for a in action_instances) / count if count > 0 else 0
        risk_class = "high" if avg_risk >= 60 else "medium" if avg_risk >= 40 else "low"
        
        html += f"""
            <tr class="{risk_class}">
                <td>{action_name}</td>
                <td>{count}</td>
                <td>{pinned_ratio:.1%}</td>
                <td>{avg_risk:.1f}</td>
            </tr>
        """
    
    html += """
        </table>
        
        <h2>Critical Production Risks</h2>
        <p>The following actions represent the highest security risk: they are used in production workflows, 
        are high risk, use secrets, and are not pinned to specific commits.</p>
        <table>
            <tr>
                <th>Repository</th>
                <th>Workflow</th>
                <th>Action</th>
                <th>Production Indicator</th>
                <th>Secrets Used</th>
                <th>Risk Score</th>
            </tr>
    """
    
    # filter for critical production risks
    critical_prod_risks = [a for a in actions_data 
                          if a.get("production_workflow", False) 
                          and a["risk_level"] == "High" 
                          and a["has_secrets"] 
                          and not a["is_pinned"]]
    
    for action in sorted(critical_prod_risks, key=lambda a: a["risk_score"], reverse=True)[:30]:
        html += f"""
            <tr class="high">
                <td>{action["repository"]}</td>
                <td>{action["workflow_file"]}</td>
                <td>{action["action_name"]}</td>
                <td>{", ".join(action.get("production_indicators", []))}</td>
                <td>{", ".join(action["required_secrets"])}</td>
                <td><span class="risk-badge risk-high">{action["risk_score"]}</span></td>
            </tr>
        """
    
    html += """
        </table>
        
        <h2>Detailed Security Analysis</h2>
        <div class="tab">
            <button class="tablinks" onclick="openTab(event, 'HighRiskActions')">High Risk Actions</button>
            <button class="tablinks" onclick="openTab(event, 'UnpinnedActions')">Unpinned Actions</button>
            <button class="tablinks" onclick="openTab(event, 'ActionsWithSecrets')">Actions With Secrets</button>
            <button class="tablinks" onclick="openTab(event, 'ProductionActions')">Production Actions</button>
            <button class="tablinks" onclick="openTab(event, 'PrivilegedActions')">Privileged Actions</button>
            <button class="tablinks" onclick="openTab(event, 'FileSystemActions')">File System Access</button>
            <button class="tablinks" onclick="openTab(event, 'NetworkActions')">Network Access</button>
        </div>
    """
    
    # high risk actions tab
    html += """
        <div id="HighRiskActions" class="tabcontent">
            <h3>High Risk Actions</h3>
            <p>Actions with a risk score of 70 or higher. These should be carefully reviewed and updated as needed.</p>
            <table>
                <tr>
                    <th>Repository</th>
                    <th>Workflow</th>
                    <th>Action</th>
                    <th>Version</th>
                    <th>Pinned</th>
                    <th>Uses Secrets</th>
                    <th>Risk Score</th>
                </tr>
    """
    
    # add high risk actions (limit to top 50 for brevity)
    high_risk_actions = [a for a in actions_data if a["risk_level"] == "High"]
    for action in sorted(high_risk_actions, key=lambda a: a["risk_score"], reverse=True)[:50]:
        html += f"""
                <tr>
                    <td>{action["repository"]}</td>
                    <td>{action["workflow_file"]}</td>
                    <td>{action["action_name"]}</td>
                    <td>{action["action_version"]}</td>
                    <td>{"Yes" if action["is_pinned"] else "No"}</td>
                    <td>{"Yes" if action["has_secrets"] else "No"}</td>
                    <td><span class="risk-badge risk-high">{action["risk_score"]}</span></td>
                </tr>
        """
    
    html += """
            </table>
        </div>
    """
    
    # unpinned actions tab
    html += """
        <div id="UnpinnedActions" class="tabcontent">
            <h3>Unpinned Actions</h3>
            <p>Actions that are not pinned to a specific commit SHA. These should be updated to use specific commit hashes for security.</p>
            <table>
                <tr>
                    <th>Repository</th>
                    <th>Workflow</th>
                    <th>Action</th>
                    <th>Version</th>
                    <th>Risk Level</th>
                </tr>
    """
    
    # add unpinned actions (limit to top 50 for brevity)
    unpinned_actions = [a for a in actions_data if not a["is_pinned"]]
    for action in sorted(unpinned_actions, key=lambda a: a["risk_score"], reverse=True)[:50]:
        risk_class = "high" if action["risk_level"] == "High" else "medium" if action["risk_level"] == "Medium" else "low"
        html += f"""
                <tr class="{risk_class}">
                    <td>{action["repository"]}</td>
                    <td>{action["workflow_file"]}</td>
                    <td>{action["action_name"]}</td>
                    <td>{action["action_version"]}</td>
                    <td><span class="risk-badge risk-{action["risk_level"].lower()}">{action["risk_level"]}</span></td>
                </tr>
        """
    
    html += """
            </table>
        </div>
    """
    
    # actions with secrets tab
    html += """
        <div id="ActionsWithSecrets" class="tabcontent">
            <h3>Actions With Secrets</h3>
            <p>Actions that use secrets, which can be a security risk if the action is not trustworthy.</p>
            <table>
                <tr>
                    <th>Repository</th>
                    <th>Workflow</th>
                    <th>Action</th>
                    <th>Secrets Used</th>
                    <th>Risk Level</th>
                </tr>
    """
    
    # add actions with secrets (limit to top 50 for brevity)
    secret_actions = [a for a in actions_data if a["has_secrets"]]
    for action in sorted(secret_actions, key=lambda a: a["risk_score"], reverse=True)[:50]:
        risk_class = "high" if action["risk_level"] == "High" else "medium" if action["risk_level"] == "Medium" else "low"
        html += f"""
                <tr class="{risk_class}">
                    <td>{action["repository"]}</td>
                    <td>{action["workflow_file"]}</td>
                    <td>{action["action_name"]}</td>
                    <td>{", ".join(action["required_secrets"])}</td>
                    <td><span class="risk-badge risk-{action["risk_level"].lower()}">{action["risk_level"]}</span></td>
                </tr>
        """
    
    html += """
            </table>
        </div>
    """
    
    # production actions tab
    html += """
        <div id="ProductionActions" class="tabcontent">
            <h3>Production Workflow Actions</h3>
            <p>Actions used in workflows that appear to be related to production deployments or releases.</p>
            <table>
                <tr>
                    <th>Repository</th>
                    <th>Workflow</th>
                    <th>Action</th>
                    <th>Production Indicator</th>
                    <th>Pinned</th>
                    <th>Uses Secrets</th>
                    <th>Risk Level</th>
                </tr>
    """
    
    # filter and sort actions in production workflows
    production_actions = [a for a in actions_data if a.get("production_workflow", False)]
    # sort by risk score (highest first)
    production_actions.sort(key=lambda a: a["risk_score"], reverse=True)
    
    for action in production_actions[:50]:  # limit to top 50
        risk_class = "high" if action["risk_level"] == "High" else "medium" if action["risk_level"] == "Medium" else "low"
        html += f"""
                <tr class="{risk_class}">
                    <td>{action["repository"]}</td>
                    <td>{action["workflow_file"]}</td>
                    <td>{action["action_name"]}</td>
                    <td>{', '.join(action.get("production_indicators", []))}</td>
                    <td>{"Yes" if action["is_pinned"] else "No"}</td>
                    <td>{"Yes" if action["has_secrets"] else "No"}</td>
                    <td><span class="risk-badge risk-{action["risk_level"].lower()}">{action["risk_level"]}</span></td>
                </tr>
        """
    
    html += """
            </table>
        </div>
    """
    
    # privileged actions tab
    html += """
        <div id="PrivilegedActions" class="tabcontent">
            <h3>Potentially Privileged Actions</h3>
            <p>Actions that may have elevated privileges or access to sensitive resources.</p>
            <table>
                <tr>
                    <th>Repository</th>
                    <th>Workflow</th>
                    <th>Action</th>
                    <th>Privileged Reasons</th>
                    <th>Risk Level</th>
                </tr>
    """
    
    # add privileged actions (limit to top 50 for brevity)
    privileged_actions = [a for a in actions_data if a.get("privileged", False)]
    for action in sorted(privileged_actions, key=lambda a: a["risk_score"], reverse=True)[:50]:
        risk_class = "high" if action["risk_level"] == "High" else "medium" if action["risk_level"] == "Medium" else "low"
        html += f"""
                <tr class="{risk_class}">
                    <td>{action["repository"]}</td>
                    <td>{action["workflow_file"]}</td>
                    <td>{action["action_name"]}</td>
                    <td>{", ".join(action.get("privileged_reasons", ["Undetermined"]))}</td>
                    <td><span class="risk-badge risk-{action["risk_level"].lower()}">{action["risk_level"]}</span></td>
                </tr>
        """
    
    html += """
            </table>
        </div>
    """
    
    # file system access tab
    html += """
        <div id="FileSystemActions" class="tabcontent">
            <h3>Actions with File System Access</h3>
            <p>Actions that may have access to the file system, potentially including source code.</p>
            <table>
                <tr>
                    <th>Repository</th>
                    <th>Workflow</th>
                    <th>Action</th>
                    <th>File System Access Reasons</th>
                    <th>Risk Level</th>
                </tr>
    """
    
    # add file system access actions (limit to top 50 for brevity)
    fs_actions = [a for a in actions_data if a.get("file_system_access", False)]
    for action in sorted(fs_actions, key=lambda a: a["risk_score"], reverse=True)[:50]:
        risk_class = "high" if action["risk_level"] == "High" else "medium" if action["risk_level"] == "Medium" else "low"
        html += f"""
                <tr class="{risk_class}">
                    <td>{action["repository"]}</td>
                    <td>{action["workflow_file"]}</td>
                    <td>{action["action_name"]}</td>
                    <td>{", ".join(action.get("fs_access_reasons", ["Undetermined"]))}</td>
                    <td><span class="risk-badge risk-{action["risk_level"].lower()}">{action["risk_level"]}</span></td>
                </tr>
        """
    
    html += """
            </table>
        </div>
    """
    
    # network access tab
    html += """
        <div id="NetworkActions" class="tabcontent">
            <h3>Actions with Network Access</h3>
            <p>Actions that may make network requests or access external resources.</p>
            <table>
                <tr>
                    <th>Repository</th>
                    <th>Workflow</th>
                    <th>Action</th>
                    <th>Network Access Reasons</th>
                    <th>Risk Level</th>
                </tr>
    """
    
    # add network access actions (limit to top 50 for brevity)
    network_actions = [a for a in actions_data if a.get("network_access", False)]
    for action in sorted(network_actions, key=lambda a: a["risk_score"], reverse=True)[:50]:
        risk_class = "high" if action["risk_level"] == "High" else "medium" if action["risk_level"] == "Medium" else "low"
        html += f"""
                <tr class="{risk_class}">
                    <td>{action["repository"]}</td>
                    <td>{action["workflow_file"]}</td>
                    <td>{action["action_name"]}</td>
                    <td>{", ".join(action.get("network_access_reasons", ["Undetermined"]))}</td>
                    <td><span class="risk-badge risk-{action["risk_level"].lower()}">{action["risk_level"]}</span></td>
                </tr>
        """
    
    html += """
            </table>
        </div>
        
        <div class="recommendation">
            <h3>Key Recommendations</h3>
            <ol>
                <li><strong>Pin all actions to specific SHA commits</strong> for predictable, secure builds</li>
                <li><strong>Review high-risk actions</strong> that have access to secrets</li>
                <li><strong>Implement organization-wide policy</strong> for GitHub Actions usage</li>
                <li><strong>Set up continuous monitoring</strong> to detect new unpinned or high-risk actions</li>
                <li><strong>Validate third-party actions</strong> are from trusted sources and recent commits</li>
            </ol>
        </div>
        
        <div class="recommendation">
            <h3>Next Steps</h3>
            <ol>
                <li>Address high-risk actions in production pipelines first</li>
                <li>Update unpinned actions to use specific commit SHAs</li>
                <li>Implement automated scanning in CI/CD to prevent introduction of new risks</li>
                <li>Create an organization-wide security policy for GitHub Actions</li>
            </ol>
        </div>
    </body>
    </html>
    """
    
    return html

def generate_markdown_report(actions_data, stats, summary_data):
    prod_high_risk_pct = (stats["production_high_risk"]/stats["production_workflow_actions"]*100) if stats["production_workflow_actions"] > 0 else 0
    prod_unpinned_pct = (stats["production_unpinned"]/stats["production_workflow_actions"]*100) if stats["production_workflow_actions"] > 0 else 0
    prod_secrets_pct = (stats["production_with_secrets"]/stats["production_workflow_actions"]*100) if stats["production_workflow_actions"] > 0 else 0
    
    markdown = f"""# GitHub Actions Security Assessment Report

Generated on {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Executive Summary

This report provides a comprehensive security assessment of GitHub Actions usage across {stats["repositories"]} repositories. 
A total of {stats["total_actions"]} action references were analyzed, representing {stats["unique_actions"]} unique actions.

Key findings:

- **{stats["risk_distribution"]["high"]}** high-risk action references identified ({stats["risk_distribution"]["high"]/stats["total_actions"]*100:.1f}% of total)
- **{stats["unpinned_actions"]}** unpinned action references ({stats["unpinned_actions"]/stats["total_actions"]*100:.1f}% of total)
- **{stats["actions_with_secrets"]}** actions using secrets ({stats["actions_with_secrets"]/stats["total_actions"]*100:.1f}% of total)
- **{stats["production_workflow_actions"]}** actions in production workflows ({stats["production_workflow_actions"]/stats["total_actions"]*100:.1f}% of total)
- **{stats["production_high_risk"]}** high-risk actions in production workflows

## Risk Overview

| Metric | Count | Percentage |
|--------|-------|------------|
| Total Action References | {stats["total_actions"]} | 100% |
| Unique Actions | {stats["unique_actions"]} | - |
| High Risk | {stats["risk_distribution"]["high"]} | {stats["risk_distribution"]["high"]/stats["total_actions"]*100:.1f}% |
| Medium Risk | {stats["risk_distribution"]["medium"]} | {stats["risk_distribution"]["medium"]/stats["total_actions"]*100:.1f}% |
| Low Risk | {stats["risk_distribution"]["low"]} | {stats["risk_distribution"]["low"]/stats["total_actions"]*100:.1f}% |

## Action Security Metrics

| Metric | Count | Percentage |
|--------|-------|------------|
| Pinned Actions | {stats["pinned_actions"]} | {stats["pinned_actions"]/stats["total_actions"]*100:.1f}% |
| Unpinned Actions | {stats["unpinned_actions"]} | {stats["unpinned_actions"]/stats["total_actions"]*100:.1f}% |
| Using Secrets | {stats["actions_with_secrets"]} | {stats["actions_with_secrets"]/stats["total_actions"]*100:.1f}% |
| Potentially Privileged | {stats["privileged_actions"]} | {stats["privileged_actions"]/stats["total_actions"]*100:.1f}% |
| File System Access | {stats["file_system_access_actions"]} | {stats["file_system_access_actions"]/stats["total_actions"]*100:.1f}% |
| Network Access | {stats["network_access_actions"]} | {stats["network_access_actions"]/stats["total_actions"]*100:.1f}% |
| Potentially Deprecated | {stats["deprecated_actions"]} | {stats["deprecated_actions"]/stats["total_actions"]*100:.1f}% |

## Production Environment Status

| Metric | Count | Percentage |
|--------|-------|------------|
| Production Workflow Actions | {stats["production_workflow_actions"]} | {stats["production_workflow_actions"]/stats["total_actions"]*100:.1f}% |
| High Risk in Production | {stats["production_high_risk"]} | {prod_high_risk_pct:.1f}% |
| Unpinned in Production | {stats["production_unpinned"]} | {prod_unpinned_pct:.1f}% |
| Using Secrets in Production | {stats["production_with_secrets"]} | {prod_secrets_pct:.1f}% |

## Top 10 Repositories by Risk

| Repository | Risk Score | Action Count |
|------------|------------|--------------|
"""
    
    # add repository risk data
    repo_action_count = Counter([a["repository"] for a in actions_data])
    for repo, risk_score in stats["high_risk_repositories"]:
        markdown += f"| {repo} | {risk_score:.1f} | {repo_action_count[repo]} |\n"
    
    markdown += """
## Top 20 Most Used Actions

| Action | Usage Count | Pinned Ratio | Average Risk |
|--------|-------------|--------------|--------------|
"""
    
    # add top actions
    for action_name, count in stats["top_actions"]:
        # calculate pinned ratio for this action
        action_instances = [a for a in actions_data if a["action_name"] == action_name]
        pinned_count = sum(1 for a in action_instances if a["is_pinned"])
        pinned_ratio = pinned_count / count if count > 0 else 0
        
        # calculate average risk score
        avg_risk = sum(a["risk_score"] for a in action_instances) / count if count > 0 else 0
        
        markdown += f"| {action_name} | {count} | {pinned_ratio:.1%} | {avg_risk:.1f} |\n"
    
    markdown += """
## Critical Production Risks

The following actions represent the highest security risk: they are used in production workflows, are high risk, use secrets, and are not pinned to specific commits.

| Repository | Workflow | Action | Production Indicator | Secrets Used | Risk Score |
|------------|----------|--------|---------------------|--------------|------------|
"""
    
    # filter for critical production risks
    critical_prod_risks = [a for a in actions_data 
                          if a.get("production_workflow", False) 
                          and a["risk_level"] == "High" 
                          and a["has_secrets"] 
                          and not a["is_pinned"]]
    
    for action in sorted(critical_prod_risks, key=lambda a: a["risk_score"], reverse=True)[:30]:
        markdown += f"| {action['repository']} | {action['workflow_file']} | {action['action_name']} | {', '.join(action.get('production_indicators', []))} | {', '.join(action['required_secrets'][:3])}{'...' if len(action['required_secrets']) > 3 else ''} | {action['risk_score']} |\n"
    
    markdown += """
## High Risk Actions

| Repository | Workflow | Action | Version | Pinned | Uses Secrets | Risk Score |
|------------|----------|--------|---------|--------|--------------|------------|
"""
    
    # add high risk actions (limit to top 30 for readability)
    high_risk_actions = [a for a in actions_data if a["risk_level"] == "High"]
    for action in sorted(high_risk_actions, key=lambda a: a["risk_score"], reverse=True)[:30]:
        markdown += f"| {action['repository']} | {action['workflow_file']} | {action['action_name']} | {action['action_version']} | {'Yes' if action['is_pinned'] else 'No'} | {'Yes' if action['has_secrets'] else 'No'} | {action['risk_score']} |\n"

    markdown += """
## Unpinned Actions

| Repository | Workflow | Action | Version | Risk Level |
|------------|----------|--------|---------|------------|
"""
    
    # add unpinned actions (limit to top 30 for readability)
    unpinned_actions = [a for a in actions_data if not a["is_pinned"]]
    for action in sorted(unpinned_actions, key=lambda a: a["risk_score"], reverse=True)[:30]:
        markdown += f"| {action['repository']} | {action['workflow_file']} | {action['action_name']} | {action['action_version']} | {action['risk_level']} |\n"
    
    markdown += """
## Actions With Secrets

| Repository | Workflow | Action | Secrets Used | Risk Level |
|------------|----------|--------|--------------|------------|
"""
    
    # add actions with secrets (limit to top 30 for readability)
    secret_actions = [a for a in actions_data if a["has_secrets"]]
    for action in sorted(secret_actions, key=lambda a: a["risk_score"], reverse=True)[:30]:
        markdown += f"| {action['repository']} | {action['workflow_file']} | {action['action_name']} | {', '.join(action['required_secrets'][:3])}{'...' if len(action['required_secrets']) > 3 else ''} | {action['risk_level']} |\n"
    
    markdown += """
## Actions in Production Workflows

These actions are used in workflows that appear to be related to production deployments, releases, or other production environments. These should be prioritized for security improvements.

| Repository | Workflow | Action | Production Indicator | Pinned | Uses Secrets | Risk Level |
|------------|----------|--------|---------------------|--------|--------------|------------|
"""

    # filter and sort actions in production workflows
    production_actions = [a for a in actions_data if a.get("production_workflow", False)]
    # sort by risk score (highest first)
    production_actions.sort(key=lambda a: a["risk_score"], reverse=True)

    for action in production_actions[:30]:  # Limit to top 30 for markdown
        markdown += f"| {action['repository']} | {action['workflow_file']} | {action['action_name']} | {', '.join(action.get('production_indicators', []))} | {'Yes' if action['is_pinned'] else 'No'} | {'Yes' if action['has_secrets'] else 'No'} | {action['risk_level']} |\n"

    markdown += """
## Potentially Privileged Actions

Actions that may have elevated privileges or access to sensitive resources.

| Repository | Workflow | Action | Privileged Reasons | Risk Level |
|------------|----------|--------|-------------------|------------|
"""

    # add privileged actions (limit to top 30 for readability)
    privileged_actions = [a for a in actions_data if a.get("privileged", False)]
    for action in sorted(privileged_actions, key=lambda a: a["risk_score"], reverse=True)[:30]:
        markdown += f"| {action['repository']} | {action['workflow_file']} | {action['action_name']} | {', '.join(action.get('privileged_reasons', ['Undetermined']))} | {action['risk_level']} |\n"

    markdown += """
## Actions with File System Access

Actions that may have access to the file system, potentially including source code.

| Repository | Workflow | Action | File System Access Reasons | Risk Level |
|------------|----------|--------|---------------------------|------------|
"""

    # add file system access actions (limit to top 30 for readability)
    fs_actions = [a for a in actions_data if a.get("file_system_access", False)]
    for action in sorted(fs_actions, key=lambda a: a["risk_score"], reverse=True)[:30]:
        markdown += f"| {action['repository']} | {action['workflow_file']} | {action['action_name']} | {', '.join(action.get('fs_access_reasons', ['Undetermined']))} | {action['risk_level']} |\n"

    markdown += """
## Actions with Network Access

Actions that may make network requests or access external resources.

| Repository | Workflow | Action | Network Access Reasons | Risk Level |
|------------|----------|--------|------------------------|------------|
"""

    # add network access actions (limit to top 30 for readability)
    network_actions = [a for a in actions_data if a.get("network_access", False)]
    for action in sorted(network_actions, key=lambda a: a["risk_score"], reverse=True)[:30]:
        markdown += f"| {action['repository']} | {action['workflow_file']} | {action['action_name']} | {', '.join(action.get('network_access_reasons', ['Undetermined']))} | {action['risk_level']} |\n"

    markdown += """
## Key Recommendations

1. **Pin all actions to specific SHA commits** for predictable, secure builds
2. **Review high-risk actions** that have access to secrets
3. **Implement organization-wide policy** for GitHub Actions usage
4. **Set up continuous monitoring** to detect new unpinned or high-risk actions
5. **Validate third-party actions** are from trusted sources and recent commits

## Next Steps

1. Address high-risk actions in production pipelines first
2. Update unpinned actions to use specific commit SHAs
3. Implement automated scanning in CI/CD to prevent introduction of new risks
4. Create an organization-wide security policy for GitHub Actions
"""
    
    return markdown

def main():
    print("loading actions inventory data...")
    actions_data = load_inventory_data()
    
    print("loading summary statistics...")
    summary_data = load_summary_data()
    
    print("classifying actions and calculating risk scores...")
    classified_actions = classify_actions(actions_data)
    
    print("generating statistics...")
    stats = generate_statistics(classified_actions)
    
    print("generating HTML report...")
    html_report = generate_html_report(classified_actions, stats, summary_data)
    with open(output_html, "w") as f:
        f.write(html_report)
    
    print("generating markdown report...")
    markdown_report = generate_markdown_report(classified_actions, stats, summary_data)
    with open(output_markdown, "w") as f:
        f.write(markdown_report)
    
    print(f"reports generated successfully:")
    print(f"  - HTML Report: {output_html}")
    print(f"  - Markdown Report: {output_markdown}")

if __name__ == "__main__":
    main()
