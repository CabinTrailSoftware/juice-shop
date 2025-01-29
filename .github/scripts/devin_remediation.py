import asyncio
import aiohttp
import os
import subprocess
from datetime import datetime

# Environment variables
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY")
SONAR_TOKEN = os.getenv("SONAR_TOKEN")
DEVIN_API_KEY = os.getenv("DEVIN_API_KEY")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
SONAR_ORG = os.getenv("SONAR_ORG")
SONAR_PROJECT_KEY = os.getenv("SONAR_PROJECT_KEY")
DEVIN_API_BASE = "https://api.devin.ai/v1"

def get_existing_vulnerability_fixes():
    """Get list of existing vulnerability fixes from branches"""
    result = subprocess.run(["git", "branch"], capture_output=True, text=True)
    branches = result.stdout.strip().split('\n')
    return [b.strip() for b in branches if b.strip().startswith('devin/')]

async def get_sonarcloud_issues():
    url = "https://sonarcloud.io/api/issues/search"
    headers = {"Authorization": f"Bearer {SONAR_TOKEN}"}
    params = {
        "organization": SONAR_ORG,
        "projectKeys": SONAR_PROJECT_KEY,
        "types": "VULNERABILITY",
        "statuses": "OPEN"
    }
    
    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, params=params) as response:
            if response.status != 200:
                print(f"Error getting SonarCloud issues: {await response.text()}")
                return []
            result = await response.json()
            print(f"Found {len(result.get('issues', []))} issues")
            return result.get('issues', [])

async def create_devin_session(issue):
    # Check if fix already exists
    existing_fixes = get_existing_vulnerability_fixes()
    branch_name = f"devin/{issue['key']}-fix-nosql-injection"
    
    if branch_name in existing_fixes:
        print(f"Fix already exists for issue {issue['key']}, skipping...")
        return None
    
    print(f"Creating branch: {branch_name}")
    subprocess.run(["git", "checkout", "-b", branch_name])
    
    async with aiohttp.ClientSession() as session:
        headers = {"Authorization": f"Bearer {DEVIN_API_KEY}"}
        data = {
            "prompt": f"Fix the following vulnerability in {GITHUB_REPOSITORY}: {issue['message']} in file {issue['component']}. Implement the fix and provide a detailed commit message explaining the changes.",
            "idempotent": True
        }
        
        async with session.post(f"{DEVIN_API_BASE}/sessions", json=data, headers=headers) as response:
            if response.status != 200:
                print(f"Error creating Devin session: {await response.text()}")
                return None
            result = await response.json()
            print(f"Devin session created: {result}")
            return result

async def get_devin_result(session_id):
    async with aiohttp.ClientSession() as session:
        headers = {"Authorization": f"Bearer {DEVIN_API_KEY}"}
        async with session.get(f"{DEVIN_API_BASE}/session/{session_id}", headers=headers) as response:
            if response.status != 200:
                print(f"Error getting Devin result: {await response.text()}")
                return None
            return await response.json()

async def commit_changes(issue):
    subprocess.run(["git", "add", "."])
    
    commit_message = (
        f"fix: Remediate NoSQL injection vulnerability\n\n"
        f"Issue Key: {issue['key']}\n"
        f"Component: {issue['component']}\n"
        f"Fixed by Devin AI at {datetime.now().isoformat()}\n"
        f"\nCo-authored-by: github-actions[bot] <github-actions[bot]@users.noreply.github.com>"
    )
    
    subprocess.run(["git", "commit", "-m", commit_message])
    
    remote_url = f"https://x-access-token:{GITHUB_TOKEN}@github.com/{GITHUB_REPOSITORY}.git"
    subprocess.run(["git", "remote", "set-url", "origin", remote_url])
    
    result = subprocess.run(["git", "push", "origin", "HEAD"], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error pushing changes: {result.stderr}")
    else:
        print(f"Successfully pushed changes")

async def main():
    try:
        issues = await get_sonarcloud_issues()
        processed_issues = set()
        
        for issue in issues:
            if issue['key'] in processed_issues:
                continue
                
            print(f"Processing issue: {issue['key']}")
            session_data = await create_devin_session(issue)
            
            if session_data:
                session_id = session_data["session_id"]
                while True:
                    result = await get_devin_result(session_id)
                    if not result:
                        break
                    
                    if result["status_enum"] in ["blocked", "stopped"]:
                        if "structured_output" in result and "fix" in result["structured_output"]:
                            await commit_changes(issue)
                        break
                    await asyncio.sleep(5)
                
                processed_issues.add(issue['key'])
                
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        raise

if __name__ == "__main__":
    asyncio.run(main())
