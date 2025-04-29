# SecretOps Tool

SecretOps Tool is a simple and flexible command-line tool that helps you manage secrets in AWS SecretsManager. It can also back up your secrets into 1Password nad local if you want.

This tool is useful if you are working in DevOps, GitOps, or cloud setups. It makes it easier to export, back up, restore, compare, and edit your secrets without complicated setups.

Main things you can do:

- Export key names from AWS SecretsManager
- Back up secrets to local files or 1Password
- Restore secrets from backups
- Compare secrets with backups, 1Password, or GitOps repos
- Edit secrets by adding, updating, or deleting keys
- Fully supports AWS SSO profiles

---

## 📦 Installation

Clone the repository and install what you need:

```bash
git clone https://github.com/narcislinux/Secretops-aws.git
cd Secretops-aws
pip install boto3 inquirer pyyaml
```

---

## ⚙️ Requirements

- Python 3.7+
- AWS CLI with SSO profile configured
- Python packages: `boto3`, `inquirer`, `PyYAML`
- 1Password CLI (`op`) (only needed if using 1Password backup)
- Git installed (only needed if using GitOps diff)

---

## 🛠️ Usage

All commands need you to set these three options:
- `--env` → environment (like `test`, `prod`, etc.)
- `--aws-region` → AWS region
- `--aws-profile` → your AWS SSO profile name

### 🔰 Quick example of a full command

```bash
python Secretops-aws.py \
  --env test \
  --aws-region eu-west-1 \
  --aws-profile test-account \
  --secret my-secret-name \
  --edit update \
  --edit-key API_KEY \
  --edit-value xyz123 \
  --backup both \
  --backup-folder ./Backup \
  --op-vault Private
```

---

### 🗂 Export key names

Save all the key names inside a secret into a file:

```bash
python Secretops-aws.py \
  --env test \
  --aws-region eu-west-1 \
  --aws-profile test-account \
  --secret my-secret-name \
  --output-file
```

### 💾 Backup secret

Add these options to make a backup while doing other things:

```bash
--backup local|1password|both \
--backup-folder ./Backup \
--op-vault Private
```

You can use backup with **any action**.

### ♻️ Restore secret

- Restore from a local file:
```bash
--restore local \
--restore-from ./Backup/your-backup-file.json
```

- Restore from 1Password:
```bash
--restore op \
--restore-from secret-title-in-1password
```

### 🧪 Diff secrets

> ⚠️ For GitOps mode, repositories with defined keys are targeted. it will scans the files to ensure that the keys are referenced in files, especially for GitOps repository include k8s manifests file.

- Compare with local backup:

```bash
--diff local \
--diff-path ./Backup/your-backup.json
```

- Compare with 1Password:
```bash
--diff op \
--diff-path your-title-in-1password
```

- Compare with GitOps repo (SSH only):
```bash
--diff gitops \
--diff-path git@gitlab.com:your-org/gitops.git
```

You can also add `--output-file` to save a `.csv` report for GitOps mode.

### ✏️ Update a secret

- Update a single key:
```bash
--edit update \
--edit-key MY_KEY \
--edit-value MY_VALUE
```

- Update from a YAML file:
```bash
--edit update \
--edit-file ./update-values.yaml
```

Example YAML:
```yaml
DATABASE_USER: admin
DATABASE_PASSWORD: supersecret
API_TOKEN: abcd1234
```

### 🧹 Delete or mark keys

Delete keys or mark them for future deletion:

```bash
--edit delete \
--edit-guid git@gitlab.com:your-org/gitops.git
```

Optional fast marking:
```bash
--edit-label y   # Mark keys for deletion automatically
--edit-label n   # Delete keys immediately
```

---

## 📜 License

This project is licensed under the Apache 2.0 License.

---

## 🙌 Contribution

Feel free to open issues, ideas, or pull requests!

---

