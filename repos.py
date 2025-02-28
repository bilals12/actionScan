import os
import requests
from dotenv import load_dotenv
load_dotenv()
token = os.environ["GITHUB_TOKEN"];
org = os.environ["GITHUB_ORG"];
repos = [];
url = f"https://api.github.com/orgs/{org}/repos?per_page=100";
while url:
    r = requests.get(url, headers={"Authorization": f"token {token}"});
    repos.extend([repo["full_name"] for repo in r.json()]);
    url = r.links["next"]["url"] if "next" in r.links else None;
with open("repo_list.txt", "w") as f:
    f.write("\n".join(repos))

