help: ## Display this help screen
	@grep -h \
		-E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
# usage:
# make download-setup -e degree=20 dir=./test_data/.params
download-setup:
	sh scripts/download_setup.sh ${degree} ${dir}

# usage:
# make setup-test-data -e dir=./test_data/.configs
setup-test-data:
	sh scripts/setup_test_data.sh ${dir}
