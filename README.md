asdasd# di-authentication-api

## Pre-commit hook

The repo has config set up for a custom pre-commit hook in `.pre-commit-config.yaml`.
Pre-commit checks include applying formatting, so after the script has run you may see files updated with formatting changes.

To implement the pre-commit hook, you will need to install pre-commit:

```shell script
brew install pre-commit
```

and then set up the hook by running

```shell script
pre-commit install
```
