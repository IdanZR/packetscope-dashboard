# Working with Git

Run these commands from the directory containing `app.py` and `.git`.

## Start a change

```powershell
git switch main
git pull --ff-only
git switch -c feature/describe-your-change
```

Edit the relevant files, then run the core tests:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
git status --short
git diff
```

## Create a commit and push

Stage the files deliberately. For example, after editing documentation:

```powershell
git add README.md docs/SUBMISSION_CHECKLIST.md
git diff --cached --check
git diff --cached
git commit -m "docs: clarify installation and submission instructions"
git push -u origin feature/describe-your-change
```

Open a pull request into `main` on GitHub, review the changes and merge it. For a small change committed directly to `main`, use `git push origin main` after review. Do not force-push shared history.

## Check the connection

```powershell
git remote -v
git branch -vv
git log --oneline -5
git status
```

The remote is `https://github.com/IdanZR/packetscope-dashboard.git`. GitHub access must use your own authenticated account. Never put a password, API key or access token in a remote URL, source file or commit message.

`.gitignore` excludes virtual environments, model weights, secret files, generated archives and captures outside `sample_data/`. Only synthetic fixtures belong in `sample_data/`; do not use `git add -f` for real captures. Include actual coursework captures separately in the final assignment ZIP after reviewing their contents.

`.gitattributes` keeps source text consistent and preserves Windows line endings for `.bat` scripts. Existing commits are an initial source snapshot followed by documentation/setup work; they are not a reconstruction of development history.
