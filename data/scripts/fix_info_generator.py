# This script was used to generate the missing fix info based on slugs present in project_info.csv, and can be adapted to generate method level information for any project given key identifiers.
# It leverages the Github API to request a commit diff, and then uses the Gemini API to generate data in accordance with the standards defined in contributing.md.


import requests
import csv
import re
import time
import base64
from google import genai
from pydantic import BaseModel, Field
from typing import Optional, List
import os
from dotenv import load_dotenv

# Setup APIs and open CSVs
load_dotenv()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Accept": "application/vnd.github.patch",
    "X-GitHub-Api-Version": "2026-03-10"
}
BASE_URL = "https://api.github.com"


api_key = os.getenv("GEMINI_API_KEY")

class Row(BaseModel):
    related: List[bool] = Field(description="Is this change related to the CVE, not a pure addition, and part of a method?")
    file_name: List[str] = Field(description="Name of file change is in.")
    class_name: List[str] = Field(description="Class the change is in.")
    class_start: List[int] = Field(description="Starting line number of the class.")
    class_end: List[int] = Field(description="Ending line number of the class.")
    method_name: List[str] = Field(description="Method the change is in, e.g. evaluate")
    method_start: List[int] = Field(description="Starting line number of the method.")
    method_end: List[int] = Field(description="Ending line number of the class.")
    method_signature: List[str] = Field(description="Full method signature, e.g. boolean evaluate(byte)")

client = genai.Client()

projects = open('project_info.csv', newline='')
fix = open('fix_info.csv', newline='')
missing_fix = open('missing_fix_info.csv', 'w', newline='', encoding='utf-8')

p = csv.reader(projects)
f = csv.reader(fix)
m = csv.writer(missing_fix)
m.writerow(['project_slug','cve_id','github_username','github_repository_name','commit','file','class','class_start','class_end','method','method_start','method_end','signature'])

# Select missing projects
included_slugs = set()

for row in f:
    included_slugs.add(row[0])

for row in p:
    if row[1] not in included_slugs:
        print("ran")
        cve = row[2]
        organization = row[5]
        repository = row[6]
        commit = row[11]
        if cve == "" or organization == "" or repository == "" or commit == "":
            print(f"Null value for project {row[1]}")
            continue
        if ";" in commit:
            print(f"Multiple commits for project {row[1]}")

        # Find and pull full changed files
        response = requests.get(f"{BASE_URL}/repos/{organization}/{repository}/commits/{commit}", headers=HEADERS)
        if not response.ok:
            print(f"Diff call failed for project {row[1]}")
            continue
        diff = response.text
        changed_paths = set(re.findall(r"b/(.*)\.java", diff))
        

        all_diffs = ""
        for diff_file in changed_paths:
            path = diff_file + ".java"
            response_per = requests.get(f"{BASE_URL}/repos/{organization}/{repository}/contents/{path}?ref={commit}", headers=HEADERS)
            if not response_per.ok:
                print(f"Diff call failed for project {row[1]}")
                continue
            full_file = base64.b64decode(response_per.json()['content']).decode('utf-8')
            time.sleep(5)
            all_diffs += full_file + "\n"

        prompt = f"""
        You are a security expert. Your goal, given a CVE, a patch diff, and the full files referenced in the diff,
        to identify whether each change in the diff satisfies the following criteria:
        The change occurs within a method. That method is preexisting and is modified, not a pure addition/ deletion.
        It is directly related to patching the CVE. If the change does not satisfy the criteria, return false for
        related and set the other fields to null. Otherwise, provide the requested information about the file, class
        and method in which the change is made. Make certain to provide output for EVERY change in the diff. Each
        output field is a List, provide an entry in each list for EVERY change.

        CVE: {cve}

        Diff: {diff}

        All files referenced in the diff: {all_diffs}
        """

        response = client.models.generate_content(
            model="gemini-3.1-pro-preview",
            contents=prompt,
            config={
                "tools": [
                    {"google_search": {}},
                ],
                "response_mime_type": "application/json",
                "response_schema": Row.model_json_schema(),
            },
        )

        output = Row.model_validate_json(response.text)
        print(f"Project: {row[1]} successful")

        # Write to CSV
        count = 0
        for i in output.related:
            if i:
                to_add = [row[1], cve, organization, repository, commit, output.file_name[count], output.class_name[count], output.class_start[count], output.class_end[count], output.method_name[count], output.method_start[count], output.method_end[count], output.method_signature[count]]
                m.writerow(to_add)
            count += 1

projects.close()
fix.close()
missing_fix.close()
