#!/usr/bin/env python3
import os
import json
import yaml
import re
import csv
from pathlib import Path
import sys
from collections import defaultdict

# output files
actions_inventory_json = "processed/actions_inventory.json"
actions_inventory_csv = "processed/actions_inventory.csv"
actions_summary_json = "processed/actions_summary.json"

# proceed only if directory exists
os.makedirs(os.path.dirname(actions_inventory_json), exist_ok=True)

def extract_actions():
    print("extracting actions from workflows...")

    # path to raw workflow data
    raw_data_dir = Path("data/raw")
    
    # store actions data
    actions_data = []

    # track stats
    stats = {
            "total_repositories": 0,
            "repos_with_workflows": 0,
            "total_workflows": 0,
            "total_actions": 0,
            "unique_actions": set(),
            "actions_usage_count": defaultdict(int),
            "unpinned_actions": 0,
            "pinned_actions":0
            }

    # list all repo directories
    repo_dirs = list(raw_data_dir.glob("*"))
    total_repos = len(repo_dirs)

    # process each repo
    for i, repo_dir in enumerate(repo_dirs):
        print(f"processing repository {i+1}/{total_repos}: {repo_dir.name}...", end="\r")
        workflows_file = repo_dir / "workflows.json"
        if not workflows_file.exists():
            continue

        try:
            with open(workflows_file, "r") as f:
                repo_data = json.load(f)

            repo_name = repo_data["name"]
            workflows = repo_data.get("workflows", [])

            if not workflows:
                continue

            stats["total_repositories"] += 1
            stats["repos_with_workflows"] += 1
            stats["total_workflows"] += len(workflows)

            for workflow in workflows:
                try:
                    workflow_name = workflow.get("name", "")
                    workflow_path = workflow.get("path", "")
                    workflow_content = workflow.get("content", "")

                    # parse YAML
                    workflow_yaml = yaml.safe_load(workflow_content)

                    if not workflow_yaml:
                        continue

                    # extract actions from jobs
                    if "jobs" in workflow_yaml:
                        for job_name, job_config in workflow_yaml["jobs"].items():
                            # check for job-level uses (reusable workflows)
                            if "uses" in job_config:
                                action_ref = job_config["uses"]
                                process_action(actions_data, stats, repo_name, workflow_name, workflow_path, job_name, "job-level", action_ref, job_config)

                            # process steps within job
                            if "steps" in job_config:
                                for step_idx, step in enumerate(job_config["steps"]):
                                    if "uses" in step:
                                        action_ref = step["uses"]
                                        step_name = step.get("name", f"step-{step_idx+1}")
                                        process_action(actions_data, stats, repo_name, workflow_name, workflow_path, job_name, step_name, action_ref, step)

                except Exception as e:
                    print(f"\nerror processing workflow {workflow_name} in {repo_name}: {e}")
        except Exception as e:
            print(f"\nerror processing repository {repo_dir.name}: {e}")

    print("\nprocessing complete!")

    # convert set of unique actions to list for JSON serialization
    stats["unique_actions"] = list(stats["unique_actions"])
    stats["top_actions"] = sorted(stats["actions_usage_count"].items(), key=lambda x: x[1], reverse=True)[:50]

    # save results
    with open(actions_inventory_json, "w") as f:
        json.dump(actions_data, f, indent=2)

    with open(actions_summary_json, "w") as f:
        # convert defaultdict to regular dict for JSON serialization
        action_usage = dict(stats["actions_usage_count"])
        stats_json = {**stats, "actions_usage_count": action_usage}
        json.dump(stats_json, f, indent=2)

    # generate csv
    with open(actions_inventory_csv, "w", newline="") as f:
        fieldnames = actions_data[0].keys() if actions_data else []
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for action in actions_data:
            writer.writerow(action)

    return actions_data, stats

def process_action(actions_data, stats, repo_name, workflow_name, workflow_path, job_name, step_name, action_ref, config):
    
    # extract action name + version
    parts = action_ref.split('@')
    action_name = parts[0]
    action_version = parts[1] if len(parts) > 1 else "unspecified"

    # pinned? (using SHA)
    is_pinned = bool(re.match(r'^[0-9a-f]{40}$', action_version))

    # update stats
    stats["total_actions"] += 1
    stats["unique_actions"].add(action_name)
    stats["actions_usage_count"][action_name] += 1

    if is_pinned:
        stats["pinned_actions"] += 1
    else:
        stats["unpinned_actions"] += 1

    # extract secrets usage
    required_secrets = extract_secrets(config)

    # create action entry
    action_entry = {
            "repository": repo_name,
            "workflow_file": workflow_name,
            "workflow_path": workflow_path,
            "job_name": job_name,
            "step_name": step_name,
            "action_name": action_name,
            "action_version": action_version,
            "full_reference": action_ref,
            "is_pinned": is_pinned,
            "has_secrets": len(required_secrets) > 0,
            "required_secrets": required_secrets,
            "is_third_party": not (action_name.startswith("actions/") or action_name.startswith("github/")),
            "with_params": config.get("with", {})
            }
    actions_data.append(action_entry)

def extract_secrets(config):
    """extract secrets used in the step/job configuration"""
    required_secrets = []

    # check 'with' params
    if "with" in config:
        for param, value in config["with"].items():
            if isinstance(value, str) and "${{" in value and "secrets." in value:
                secret_matches = re.findall(r'\$\{\{\s*secrets\.([A-Za-z0-9_-]+)\s*\}\}', value)
                required_secrets.extend(secret_matches)

    # check 'env' params
    if "env" in config:
        for key, value in config["env"].items():
            if isinstance(value, str) and "${{" in value and "secrets." in value:
                secret_matches = re.findall(r'\$\{\{\s*secrets\.([A-Za-z0-9_-]+)\s*\}\}', value)
                required_secrets.extend(secret_matches)

    # check 'secrets' params for reusable workflows
    if "secrets" in config:
        if isinstance(config["secrets"], dict):
            required_secrets.extend(list(config["secrets"].keys()))
        elif isinstance(config["secrets"], list):
            required_secrets.extend(config["secrets"])

    return list(set(required_secrets)) # remove duplicates

def print_summary(stats):
    """print summary of extracted actions"""
    print("\n---GitHub Actions Inventory Summary ---\n")
    print(f"total repositories processed: {stats['total_repositories']}")
    print(f"repositories with workflows: {stats['repos_with_workflows']}")
    print(f"total workflows: {stats['total_workflows']}")
    print(f"total actions: {stats['total_actions']}")
    print(f"unique actions: {stats['unique_actions']}")
    print(f"pinned actions: {stats['pinned_actions']} ({stats['pinned_actions']/stats['total_actions']*100:.2f}%)")
    print(f"unpinned actions: {stats['unpinned_actions']} ({stats['unpinned_actions']/stats['total_actions']*100:.2f}%)")

    print("\ntop 10 most used actions:")
    for action, count in sorted(stats["actions_usage_count"].items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f" - {action}: {count} uses")

    print(f"\ndetailed inventory saved to: {actions_inventory_json} and {actions_inventory_csv}")
    print(f"summary stats saved to: {actions_summary_json}")

if __name__ == "__main__":
    # run extraction
    actions_data, stats = extract_actions()

    # print summary
    print_summary(stats)

