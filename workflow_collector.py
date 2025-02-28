import os
import json
import requests
import base64
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()
token = os.environ["GITHUB_TOKEN"]
headers = {"Authorization": f"token {token}"}

with open("repo_list.txt", "r") as f:
    repos = [line.strip() for line in f]

for repo in repos:
    print(f"processing {repo}...")
    repo_data = {"name": repo, "workflows": []}

    # get workflow files from .github/workflows
    url = f"https://api.github.com/repos/{repo}/contents/.github/workflows"
    try:
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            files = r.json()
            for file in files:
                if file["type"] == "file" and (file["name"].endswith(".yml") or file["name"].endswith(".yaml")):
                    content_r = requests.get(file["url"], headers=headers)
                    if content_r.status_code == 200:
                        content = base64.b64decode(content_r.json()["content"]).decode("utf-8")
                        repo_data["workflows"].append({
                            "name": file["name"],
                            "path": file["path"],
                            "content": content
                            })
        # save data
        os.makedirs(f"data/raw/{repo.replace('/', '_')}", exist_ok=True)
        with open(f"data/raw/{repo.replace('/', '_')}/workflows.json", "w") as out_f:
                  json.dump(repo_data, out_f, indent=2)
    except Exception as e:
                  print(f"error processing {repo}: {e}")

