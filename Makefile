.DEFAULT_GOAL := help

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

READ_SECRETS_SCRIPTS_IN_MODULES=$(shell find ci/terraform -type f -name read_secrets.sh)
.PHONY: update_read_secrets_scripts
update_read_secrets_scripts: ## Update read_secrets.sh in all terraform modules from scripts/read_secrets__main.sh
update_read_secrets_scripts: $(READ_SECRETS_SCRIPTS_IN_MODULES)

$(READ_SECRETS_SCRIPTS_IN_MODULES): scripts/read_secrets__main.sh
	@cp -pvf $< $@
