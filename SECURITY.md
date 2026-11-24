# Security policy

## What is in scope

- `itam_ImportIntuneDevices.ps1`, the import script that reads devices from Microsoft Intune and writes models, assets and images to an au2mator instance
- `models.json` and `categories.json`, the model catalog. The script can download both files from this repository, see "Keeping the catalog current in the import script" in the README

Examples: a way to make the script run unintended code, leak credentials or tokens into logs, follow a download to a host that is not allow-listed, or accept manipulated catalog data.

## How to report a vulnerability

Please do **not** open a public issue or pull request for a security problem.

- Use GitHub's private reporting: **Security → Report a vulnerability** on this repository (if the button is missing, use e-mail), or
- write to **michael.seidl@au2mator.com** with the subject "Security: au2mator-AssetManagement".

Please include what you found, how to reproduce it and which version or commit it concerns. You will get a reply within a few working days. We fix confirmed problems as soon as we can and credit you in the release notes if you like.

## Supported versions

Only the current state of `main` is maintained.

## Notes for operators

- The automatic download of the catalog files is **off by default** (`$DownloadModelFilesFromGitHub = $false`). If you switch it on, set `$ModelFilesBranch` to a release tag and review changes before moving to a newer tag.
- Run the import with a dedicated app registration that has only the permissions it needs, and keep tokens out of the script file.
