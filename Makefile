ROSWELL_VERSION := v23.10.14.114
SBCL_VERSION := 2.5.10
TEST_FILE := tests/rbac-tests.lisp

install-roswell:
	@if ! which ros > /dev/null 2>&1; then \
		echo "Roswell not found. Installing..."; \
		curl -L $(ROSWELL_BASE_URL)/$(ROSWELL_VERSION)/roswell_$(subst v,,$(ROSWELL_VERSION))-1_amd64.deb --output roswell.deb; \
		sudo dpkg -i roswell.deb; \
		ros install sbcl-bin/$(SBCL_VERSION); \
		ros use sbcl-bin/$(SBCL_VERSION); \
		echo "Roswell installation complete."; \
	else \
		echo "Roswell already installed. Skipping..."; \
	fi
	touch $@

install-dependencies:
	ros install postmodern
	ros install fiveam
	ros install cl-csv
	ros install trivial-utf-8
	ros install ironclad
	ros install swank
	ros install mgl-pax
	ros install macnod/dc-dlist/v1.0
	ros install macnod/dc-ds/v0.5
	ros install macnod/dc-time/v0.5
	ros install macnod/p-log/v0.9
	ros install macnod/dc-eclectic/v0.51

test:
	scripts/run-tests "$(TEST_FILE)"

compile:
	DB_HOST="127.0.0.1" \
	DB_PORT="5436" \
	DB_NAME="rbac" \
	DB_USER="rbac" \
	DB_PASSWORD="rbac-password" \
	ADMIN_PASSWORD="admin-password-1" \
	DB_CONTAINER="pg-rbac-test" \
	RBAC_REPL="false" \
	RUN_TESTS="false" \
	SKIP_DB="true" \
	ros run -- --disable-debugger \
		--eval '(asdf:load-system :rbac :force t)' \
    --load "$(TEST_FILE)" \
	  --quit; \
	if [ $$? -eq 0 ]; then \
		echo \
		echo "Compilation successful."; \
	else \
		echo \
		echo "Compilation failed."; \
	fi

test-ci:
	ros run -- --disable-debugger --load "$(TEST_FILE)" --quit

repl:
	scripts/rbac-tests-repl start "$(TEST_FILE)"

docs:
	scripts/generate-readme "$(TEST_FILE)"

.PHONY: install-roswell install-dependencies test
.DEFAULT_GOAL := test
