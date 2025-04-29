import boto3
import json
import os
import subprocess
import argparse
import shutil
import tempfile
import difflib
import csv
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

# ---------------------------
# CLI Argument Parsing
# ---------------------------

parser = argparse.ArgumentParser(
    description=(
        """
        This tool helps you interact with AWS SecretsManager in a more structured and automated way:

        - Export secret key names to a local file
        - Backup secrets to a local folder or upload them as documents to 1Password
        - Compare existing secrets with local backups, 1Password documents, or GitOps repositories
        """
    ),
    epilog="""
Examples:

1. Backup secret to local folder and 1Password, and export key names to a file:

  python script.py \
    --env test \
    --aws-region eu-west-1 \
    --aws-profile eks-test \
    --secret my-secret-name \
    --backup both \
    --backup-folder ./Backup \
    --op-vault Private \
    --output-file

2. Only export key names from a secret:

  python script.py \
    --env test \
    --aws-region eu-central-1 \
    --aws-profile eks-test \
    --secret my-secret-name \
    --output-file

3. Diff with local backup:

  python script.py \
    --env test \
    --aws-region eu-west-1 \
    --aws-profile eks-test \
    --secret my-secret-name \
    --diff local \
    --diff-path ./Backup/my-secret-name-test-2025-04-15-1030.json

4. Diff with 1Password document:

  python script.py \
    --env test \
    --aws-region eu-west-1 \
    --aws-profile eks-test \
    --secret my-secret-name \
    --op-vault Private \
    --diff op \
    --diff-path my-secret-name-test-2025-04-15-1030

5. GitOps usage check:

  python script.py \
    --env test \
    --aws-region eu-west-1 \
    --aws-profile eks-test \
    --secret my-secret-name \
    --diff gitops \
    --diff-path git@gitlab.com:your-org/gitops.git \
    --output-file

6. Restore from local backup:

  python script.py \
    --env test \
    --aws-region eu-west-1 \
    --aws-profile eks-test \
    --secret my-secret-name \
    --restore local \
    --restore-from ./Backup/my-secret-name-test-2025-04-17-1200.json

7. Restore from 1Password:

  python script.py \
    --env test \
    --aws-region eu-west-1 \
    --aws-profile eks-test \
    --secret my-secret-name \
    --op-vault Private \
    --restore op \
    --restore-from my-secret-name-test-2025-04-17-1200

8. Interactively delete keys (with GitOps suggestion):

  python script.py \
    --env test \
    --aws-region eu-west-1 \
    --aws-profile eks-test \
    --secret my-secret-name \
    --edit delete \
    --edit-guid git@gitlab.com:your-org/gitops.git \
    --edit-label y \
    --backup both \
    --backup-folder ./Backup \
    --op-vault Private

9. Add or update a key in the secret:

  python script.py \
    --env test \
    --aws-region eu-west-1 \
    --aws-profile eks-test \
    --secret my-secret-name \
    --edit update \
    --edit-key NEW_KEY_NAME \
    --edit-value secret_value_here

  python script.py \
    --env test \
    --aws-region eu-west-1 \
    --aws-profile eks-test \
    --secret my-secret-name \
    --edit delete \
    --edit-guid git@gitlab.com:your-org/gitops.git \
    --backup both \
    --backup-folder ./Backup \
    --op-vault Private
""",
    formatter_class=argparse.RawTextHelpFormatter
)
parser.add_argument('--env', type=str, choices=['test', 'prod', 'acc'], required=True, help='[REQUIRED] Environment name')
parser.add_argument('--aws-region', type=str, default='eu-west-1', help='AWS region name')
parser.add_argument('--aws-profile', type=str, required=True, help='[REQUIRED] AWS SSO profile name')
parser.add_argument('--backup', type=str, choices=['local', '1password', 'both'], help='Backup destination')
parser.add_argument('--op-vault', type=str, help='[CONDITIONAL] Vault name in 1Password (required if backup is 1password or both)')
parser.add_argument('--backup-folder', type=str, help='[CONDITIONAL] Backup folder path (required if backup is local or both)')
parser.add_argument('--secret', type=str, required=True, help='[REQUIRED] Name of the secret to process')
parser.add_argument('--output-file', action='store_true', help='[OPTIONAL] Enable saving list of keys to output file')
parser.add_argument('--diff', type=str, choices=['local', 'op', 'gitops'], help='[OPTIONAL] Perform diff check between AWS secret and source')
parser.add_argument('--diff-path', type=str, help='[CONDITIONAL] Path to local file, 1Password title, or Git repo URL depending on diff mode')
parser.add_argument('--restore', type=str, choices=['local', 'op'], help='[OPTIONAL] Restore from backup: local file or 1Password document')
parser.add_argument('--restore-from', type=str, help='[CONDITIONAL] Path to local file or 1Password document title/id used for restore')
parser.add_argument('--edit', type=str, choices=['delete', 'update'], help='[OPTIONAL] Edit mode: delete to remove keys interactively, update to insert or modify a key-value pair')
parser.add_argument('--edit-guid', type=str, help='[OPTIONAL] Git repo URL used for suggesting unused keys during --edit delete mode')
parser.add_argument('--edit-key', type=str, help='[CONDITIONAL] Key to update when --edit is update')
parser.add_argument('--edit-value', type=str, help='[CONDITIONAL] Value to update when --edit is update')
parser.add_argument('--edit-file', type=str, help='[ALTERNATIVE] YAML file containing key-value pairs to update in secret (used with --edit update)')
parser.add_argument('--edit-label', type=str, choices=['y', 'n'], help='[OPTIONAL] Default behavior for marking keys for deletion (y=mark, n=remove)')
args = parser.parse_args()

# ---------------------------
# Configuration Setup
# ---------------------------
ENV = args.env
AWS_REGION = args.aws_region
AWS_PROFILE_NAME = args.aws_profile
BACKUP_PREFIX = ENV
SECRET_NAME = args.secret

if args.backup in ['local', 'both'] and not args.backup_folder:
    parser.error("--backup-folder is required when --backup is 'local' or 'both'")
BACKUP_FOLDER = args.backup_folder if args.backup_folder else ''

if args.backup in ['1password', 'both'] and not args.op_vault:
    parser.error("--op-vault is required when --backup is '1password' or 'both'")
OP_VAULT = args.op_vault if args.op_vault else ''

# ---------------------------
# AWS SecretsManager
# ---------------------------
def fetch_secret(secret_name):
    session = boto3.Session(profile_name=AWS_PROFILE_NAME, region_name=AWS_REGION)
    client = session.client('secretsmanager')
    try:
        response = client.get_secret_value(SecretId=secret_name)
        secret_string = response.get('SecretString')
        if secret_string:
            data = json.loads(secret_string)
            if isinstance(data, dict):
                print(f"✅ {secret_name} → {len(data)} keys found")
                return data
            else:
                print(f"⚠️ {secret_name} is not a JSON object, skipped")
        else:
            print(f"⚠️ {secret_name} has no string value")
    except ClientError as e:
        print(f"❌ Could not retrieve {secret_name}: {e}")
    return {}

# ---------------------------
# Save keys to file
# ---------------------------
def save_keys_to_file(keys, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        for key in keys:
            f.write(f"{key}\n")
    print(f"📜 Wrote {len(keys)} keys to {filename}")

# ---------------------------
# Save full backup to JSON
# ---------------------------
def save_json_backup(data_dict, secret_name):
    os.makedirs(BACKUP_FOLDER, exist_ok=True)
    today = datetime.now().strftime('%Y-%m-%d-%H%M')
    backup_filename = f"{secret_name}-{BACKUP_PREFIX}-{today}.json"
    backup_path = os.path.join(BACKUP_FOLDER, backup_filename)
    with open(backup_path, 'w', encoding='utf-8') as f:
        json.dump(data_dict, f, indent=4)
    print(f"💾 Backup created: {backup_path}")
    return backup_path, today

# ---------------------------
# Check & Upload to 1Password
# ---------------------------
def check_existing_documents(title_prefix, vault=None):
    if vault == '':
        vault = None
    try:
        cmd = ["op", "item", "list", "--format", "json"]
        if vault:
            cmd.extend(["--vault", vault])
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode == 0:
            items = json.loads(result.stdout)
            matches = [item for item in items if item.get("title", "").startswith(title_prefix)]
            print(f"🔍 Found {len(matches)} item(s) in 1Password starting with title prefix: {title_prefix}")
            print("📋 Matching Documents:")
            print("{:<40} {:<36} {:<20}".format("Title", "ID", "Vault"))
            print("-" * 100)
            for item in matches:
                print("{:<40} {:<36} {:<20}".format(
                    item.get('title'),
                    item.get('id'),
                    item.get('vault', {}).get('name', 'N/A')
                ))
        else:
            print(f"❌ Failed to check existing items in 1Password:\n{result.stderr}")
    except Exception as e:
        print(f"⚠️ Exception while checking 1Password items: {e}")

def upload_backup_to_1password(file_path, title, vault):
    try:
        cmd = ["op", "document", "create", file_path, "--title", title, "--vault", vault]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode == 0:
            print(f"📄 Uploaded backup to 1Password as document: {title} in vault: {vault}")
        else:
            print(f"❌ Failed to upload to 1Password:\n{result.stderr}")
    except Exception as e:
        print(f"⚠️ Exception while uploading to 1Password: {e}")

# ---------------------------
# Diff Comparison Logic
# ---------------------------
def diff_local(secret_data, local_path):
    if not os.path.exists(local_path):
        print(f"❌ File not found: {local_path}")
        return
    with open(local_path, 'r', encoding='utf-8') as f:
        local_data = json.load(f)
    print("\n🔍 Diff between AWS secret and local file:")
    diff_lines = list(difflib.unified_diff(
        json.dumps(local_data, indent=2).splitlines(),
        json.dumps(secret_data, indent=2).splitlines(),
        fromfile='local', tofile='aws', lineterm=''))
    if diff_lines:
        for line in diff_lines:
            print(line)
    else:
        print("✅ No differences found. The AWS secret and local file are identical.")

def diff_op(secret_data, title=None):
    try:
        doc_title = title if title else f"{SECRET_NAME}-{BACKUP_PREFIX}"
        result = subprocess.run([
            "op", "document", "get", doc_title, "--vault", OP_VAULT
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            print(f"❌ Could not fetch document from 1Password: {result.stderr}")
            return
        op_data = json.loads(result.stdout)
        print("\n🔍 Diff between AWS secret and 1Password document:")
        diff_lines = list(difflib.unified_diff(
            json.dumps(op_data, indent=2).splitlines(),
            json.dumps(secret_data, indent=2).splitlines(),
            fromfile=doc_title, tofile='aws', lineterm=''))
        if diff_lines:
            for line in diff_lines:
                print(line)
        else:
            print("✅ No differences found. The AWS secret and 1Password document are identical.")
    except Exception as e:
        print(f"⚠️ Exception while diffing with 1Password: {e}")

def diff_gitops(secret_data, repo_path):
    if not repo_path.startswith("git@"):
        print("❌ For security reasons, only SSH Git URLs are allowed (starting with git@)")
        return
    try:
        temp_dir = tempfile.mkdtemp()
        session = subprocess.run([
            "git", "clone", "--depth=1", repo_path, temp_dir
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if session.returncode != 0:
            print(f"❌ Git clone failed: {session.stderr}")
            return

        aws_keys = set(secret_data.keys())
        used_keys = set()

        for root, _, files in os.walk(temp_dir):
            for file in files:
                if True:
                    with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for key in aws_keys:
                            if key in content:
                                used_keys.add(key)

        unused_keys = aws_keys - used_keys

        print("🔍 GitOps Secret Key Usage Check:")
        print(f"📊 Total keys in secret: {len(aws_keys)}")
        print(f"📎 Keys used in GitOps repo: {len(used_keys)}")
        print(f"🚫 Keys NOT used in GitOps repo: {len(unused_keys)}")
        if unused_keys:
            print("❌ The following keys were NOT found in the GitOps repo:")
            for key in sorted(unused_keys):
                print(f"  - {key}")
        else:
            print("✅ All secret keys are in use in the GitOps repository.")

        if args.output_file:
            csv_filename = f"gitops-usage-{SECRET_NAME}-{ENV}-{datetime.now().strftime('%Y-%m-%d-%H%M')}.csv"
            with open(csv_filename, 'w', encoding='utf-8', newline='') as csvfile:
                writer = csv.writer(csvfile, delimiter=';', quotechar='"', quoting=csv.QUOTE_MINIMAL)
                writer.writerow(['No.', 'Key', 'Used in GitOps'])  # Header
                sorted_keys = sorted(aws_keys, key=lambda k: (k in used_keys, k))
                for index, key in enumerate(sorted_keys, start=1):
                    status = 'Yes' if key in used_keys else 'No'
                    writer.writerow([index, key, status])
            print(f"📁 CSV report saved: {csv_filename}")

        shutil.rmtree(temp_dir)
    except Exception as e:
        print(f"⚠️ Error comparing GitOps repo: {e}")
        if 'temp_dir' in locals():
            shutil.rmtree(temp_dir)

# ---------------------------
# JSON Validation Helper
# ---------------------------
def validate_json(data):
    try:
        json.dumps(data)
        return True
    except (TypeError, ValueError) as e:
        print(f"❌ Invalid JSON format: {e}")
        return False

# ---------------------------
# Restore Logic
# ---------------------------
def restore_secret_from_backup(secret_name, restore_path):  
    session = boto3.Session(profile_name=AWS_PROFILE_NAME, region_name=AWS_REGION)
    client = session.client('secretsmanager')
    try:
        with open(restore_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if not validate_json(data):
            print(f"❌ Aborting restore: invalid JSON in {restore_path}")
            return
        client.put_secret_value(SecretId=secret_name, SecretString=json.dumps(data))
        print(f"🔁 Secret '{secret_name}' successfully restored from {restore_path}")
    except Exception as e:
        print(f"❌ Failed to restore secret: {e}")

def restore_secret_from_1password(secret_name, document_id_or_title):
    try:
        result = subprocess.run([
            "op", "document", "get", document_id_or_title, "--vault", OP_VAULT
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            print(f"❌ Could not fetch document from 1Password: {result.stderr}")
            return

        data = json.loads(result.stdout)
        if not validate_json(data):
            print(f"❌ Aborting restore: invalid JSON in 1Password document '{document_id_or_title}'")
            return
        session = boto3.Session(profile_name=AWS_PROFILE_NAME, region_name=AWS_REGION)
        client = session.client('secretsmanager')
        client.put_secret_value(SecretId=secret_name, SecretString=json.dumps(data))
        print(f"🔁 Secret '{secret_name}' successfully restored from 1Password: {document_id_or_title}")

    except Exception as e:
        print(f"❌ Failed to restore from 1Password: {e}")
# ---------------------------
# Edit Mode
# ---------------------------
def interactive_key_deletion(secret_data, secret_name):
    import inquirer
    gitops_unused_keys = set()
    if args.edit_guid:
        try:
            temp_dir = tempfile.mkdtemp()
            if not args.edit_guid.startswith("git@"):
                raise ValueError("Only SSH Git URLs are allowed (starting with git@)")
            subprocess.run(["git", "clone", "--depth=1", args.edit_guid, temp_dir], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            aws_keys = set(secret_data.keys())
            used_keys = set()
            for root, _, files in os.walk(temp_dir):
                for file in files:
                    with open(os.path.join(root, file), 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        for key in aws_keys:
                            if key in content:
                                used_keys.add(key)
            gitops_unused_keys = aws_keys - used_keys
            shutil.rmtree(temp_dir)
        except Exception as e:
            print(f"Warning: Failed to perform GitOps check: {e}")

    sorted_keys = sorted(secret_data.keys(), key=lambda k: (k not in gitops_unused_keys, k)) if gitops_unused_keys else sorted(secret_data.keys())
    questions = [
        inquirer.Checkbox(
            'keys_to_delete',
            message='Select keys to DELETE from the secret',
            choices=[(f"{key} {'🚫' if key in gitops_unused_keys else ''}", key) for key in sorted_keys]
        )
    ]
    answers = inquirer.prompt(questions)
    if not answers or not answers.get('keys_to_delete'):
        print("⚠️ No keys selected for deletion. Aborting.")
        return

    delete_prefix = (datetime.now() + timedelta(days=7)).strftime('%Y%m%d')

    for display_label in answers['keys_to_delete']:
        key = display_label.split(' ')[0]
        value = secret_data.pop(key, None)

        if value is not None:
            mark_for_deletion = None
            if args.edit_label:
                mark_for_deletion = args.edit_label.lower()
            else:
                mark_for_deletion = input(f"Mark key '{key}' for deletion instead of removing it now? [y/N]: ").strip().lower()

            if mark_for_deletion == 'y':
                delete_key = f"delete-{delete_prefix}::{key}"
                secret_data[delete_key] = value
                print(f"🕓 Marked '{key}' as '{delete_key}' with original value kept.")

    print(f"🧹 Removing {len(answers['keys_to_delete'])} keys and updating secret...")
    session = boto3.Session(profile_name=AWS_PROFILE_NAME, region_name=AWS_REGION)
    client = session.client('secretsmanager')
    client.put_secret_value(SecretId=secret_name, SecretString=json.dumps(secret_data))
    print(f"✅ Secret '{secret_name}' updated.")

# ---------------------------
# Backup Helper
# ---------------------------
def perform_backup(secret_data, today):
    backup_path = None
    if args.backup in ['local', 'both']:
        if not BACKUP_FOLDER:
            parser.error("--backup-folder is required when --backup is 'local' or 'both'")
        backup_path, _ = save_json_backup(secret_data, SECRET_NAME)

    if args.backup in ['1password', 'both']:
        if not OP_VAULT:
            parser.error("--op-vault is required when --backup is '1password' or 'both'")
        full_title = f"{SECRET_NAME}-{BACKUP_PREFIX}-{today}"
        upload_backup_to_1password(backup_path, full_title, OP_VAULT)
        check_existing_documents(f"{SECRET_NAME}-{BACKUP_PREFIX}")

    return backup_path


# ---------------------------
# Mode Handlers
# ---------------------------
def handle_edit_mode():
    data = fetch_secret(SECRET_NAME)
    if data is not None and validate_json(data):
        today = datetime.now().strftime('%Y-%m-%d-%H%M')
        perform_backup(data, today)

        if args.edit == 'delete':
            if not data:
                print("⚠️ Secret has no keys to delete.")
                return
            interactive_key_deletion(data, SECRET_NAME)

        elif args.edit == 'update':
            updates = {}
            if args.edit_file:
                import yaml
                try:
                    with open(args.edit_file, 'r', encoding='utf-8') as f:
                        updates = yaml.safe_load(f)
                        if not isinstance(updates, dict):
                            print("❌ YAML must contain a dictionary of key-value pairs.")
                            return
                except Exception as e:
                    print(f"❌ Failed to read edit-file: {e}")
                    return
            else:
                if not args.edit_key or not args.edit_value:
                    print("❌ --edit-key and --edit-value are required when using --edit update without --edit-file")
                    return
                updates[args.edit_key] = args.edit_value

            session = boto3.Session(profile_name=AWS_PROFILE_NAME, region_name=AWS_REGION)
            client = session.client('secretsmanager')

            for key, value in updates.items():
                if key in data:
                    print(f"⚠️ Key '{key}' already exists. It will be overwritten.")
                else:
                    print(f"➕ Adding new key: {key}")
                data[key] = value

            client.put_secret_value(SecretId=SECRET_NAME, SecretString=json.dumps(data))
            print(f"✅ {len(updates)} key(s) added/updated successfully in secret '{SECRET_NAME}'")

# ---------------------------
# Main Execution
# ---------------------------
if __name__ == '__main__':
    if args.edit:
        handle_edit_mode()
        exit(0)

    secret_data = fetch_secret(SECRET_NAME)

    if args.diff and secret_data:
        handle_diff_mode(secret_data)
        exit(0)

    if args.restore and args.restore_from:
        handle_restore_mode()
        exit(0)

    if secret_data and validate_json(secret_data):
        handle_normal_run(secret_data)
