.PHONY: check fmt clippy test license-audit test-postgres test-mysql \
        local-up local-down local-reset diff-test matrix protocol-test p2-test p2-mongo-test p3p4-test p5-test p6-test p7-smoke p7-gate

CARGO ?= cargo
COMPOSE = docker compose -f test/local/docker-compose.yml
TAG ?= smoke
ENGINE ?= all
PROFILE ?= local
DIFF_REPORT_ROOT ?= test/reports
# Loopback ports of the local test engines; override only on conflicts.
MYSQL_PORT ?= 33061
POSTGRES_PORT ?= 55432
TIDB_PORT ?= 33062
MONGO_PORT ?= 27027

check:
	cargo fmt --all -- --check
	cargo clippy --locked --workspace --all-targets -- -D warnings
	cargo test --locked --workspace

fmt:
	cargo fmt --all

clippy:
	cargo clippy --locked --workspace --all-targets -- -D warnings

test:
	cargo test --locked --workspace

license-audit:
	@if ! command -v cargo-deny >/dev/null 2>&1; then \
		echo "cargo-deny is not installed; run: cargo install cargo-deny --locked"; \
		exit 2; \
	fi
	cargo deny check --hide-inclusion-graph licenses

test-postgres:
	python3 test/rewrite/postgres.py

test-mysql:
	python3 test/rewrite/mysql.py

local-up:
	$(COMPOSE) up --detach --wait
	@$(COMPOSE) exec -T mysql sh -c 'MYSQL_PWD="$$MYSQL_ROOT_PASSWORD" mysql -uroot -e "SELECT VERSION()"'
	@$(COMPOSE) exec -T postgres sh -c 'psql -U fg_test -d postgres -tAc "SELECT version()"'
	@$(COMPOSE) exec -T mongo sh -c 'mongosh -u root -p "$$MONGO_INITDB_ROOT_PASSWORD" --quiet --eval "db.version()"'
	@TIDB_PW="$${FG_TEST_TIDB_ROOT_PASSWORD:-$$(sed -n 's/^FG_TEST_TIDB_ROOT_PASSWORD=//p' test/local/.env)}"; \
	docker run --rm --network "$${COMPOSE_PROJECT_NAME:-local}_default" -e MYSQL_PWD="$$TIDB_PW" mysql:8.0.43 \
		mysql -h tidb -P 4000 -uroot -e "SELECT VERSION()" 2>/dev/null \
		|| printf "ALTER USER 'root'@'%%' IDENTIFIED BY '%s'; SELECT VERSION();\n" "$$TIDB_PW" \
			| docker run -i --rm --network "$${COMPOSE_PROJECT_NAME:-local}_default" mysql:8.0.43 mysql -h tidb -P 4000 -uroot

local-down:
	$(COMPOSE) down

local-reset:
	$(COMPOSE) down --volumes
	$(MAKE) local-up

# Reference-versus-reference smoke on every engine.
# Endpoints come from the same variables as test/local; URLs carry passwords,
# so recipes are not echoed and fg-diff never logs them. TiDB URLs use the
# mysql:// scheme: the wire protocol is MySQL, only the port differs.
diff-test:
	@if [ -z "$$FG_TEST_MYSQL_ROOT_PASSWORD" ]; then echo "FG_TEST_MYSQL_ROOT_PASSWORD is not set (see test/local/README.md)"; exit 2; fi
	@if [ -z "$$FG_TEST_POSTGRES_PASSWORD" ]; then echo "FG_TEST_POSTGRES_PASSWORD is not set (see test/local/README.md)"; exit 2; fi
	@if [ -z "$$FG_TEST_TIDB_ROOT_PASSWORD" ]; then echo "FG_TEST_TIDB_ROOT_PASSWORD is not set (see test/local/README.md)"; exit 2; fi
	@MYSQL_BASE="mysql://root:$$FG_TEST_MYSQL_ROOT_PASSWORD@127.0.0.1:$(MYSQL_PORT)/"; \
	FG_DIFF_MYSQL_REF_URL="$$MYSQL_BASE" FG_DIFF_MYSQL_CAND_URL="$$MYSQL_BASE" \
		$(CARGO) run --locked -p fg-diff -- run --engine mysql --tag $(TAG) --report-root "$(DIFF_REPORT_ROOT)"
	@PG_BASE="postgres://fg_test:$$FG_TEST_POSTGRES_PASSWORD@127.0.0.1:$(POSTGRES_PORT)/postgres"; \
	FG_DIFF_PG_REF_URL="$$PG_BASE" FG_DIFF_PG_CAND_URL="$$PG_BASE" \
		$(CARGO) run --locked -p fg-diff -- run --engine postgres --tag $(TAG) --report-root "$(DIFF_REPORT_ROOT)"
	@TIDB_BASE="mysql://root:$$FG_TEST_TIDB_ROOT_PASSWORD@127.0.0.1:$(TIDB_PORT)/"; \
	FG_DIFF_TIDB_REF_URL="$$TIDB_BASE" FG_DIFF_TIDB_CAND_URL="$$TIDB_BASE" \
		$(CARGO) run --locked -p fg-diff -- run --engine tidb --tag $(TAG) --report-root "$(DIFF_REPORT_ROOT)"
	@MONGO_BASE="mongodb://root:$$FG_TEST_MONGO_ROOT_PASSWORD@127.0.0.1:$(MONGO_PORT)/?authSource=admin"; \
	FG_DIFF_MONGO_REF_URL="$$MONGO_BASE" FG_DIFF_MONGO_CAND_URL="$$MONGO_BASE" \
		$(CARGO) run --locked -p fg-diff -- run --engine mongodb --tag $(TAG) --report-root "$(DIFF_REPORT_ROOT)"

matrix:
	$(CARGO) run --locked -p fg-matrix -- check --root . --tag $(TAG)

protocol-test:
	@test/protocol/run.sh "$(ENGINE)"

p2-test:
	$(CARGO) build --locked -p fg-control -p fg-proxy -p fg-cli -p fg-diff
	PYTHONDONTWRITEBYTECODE=1 python3 test/p2/run.py "$(ENGINE)"

# The MongoDB branch suite drives the full production chain with a real
# pymongo oracle; it is separate from the SQL run.py registry.
p2-mongo-test:
	$(CARGO) build --locked -p fg-control -p fg-proxy -p fg-cli
	PYTHONDONTWRITEBYTECODE=1 python3 test/p2/mongo.py

p3p4-test:
	$(CARGO) build --locked -p fg-control -p fg-proxy -p fg-cli -p fg-diff
	PYTHONDONTWRITEBYTECODE=1 python3 test/p3p4/run.py "$(ENGINE)"

p5-test:
	$(CARGO) build --locked -p fg-control -p fg-proxy -p fg-cli -p fg-diff
	PYTHONDONTWRITEBYTECODE=1 python3 test/p5/run.py "$(ENGINE)"

p6-test:
	$(CARGO) build --locked -p fg-control -p fg-proxy -p fg-cli -p fg-diff
	PYTHONDONTWRITEBYTECODE=1 python3 test/p6/run.py "$(ENGINE)"

p7-smoke:
	$(CARGO) build --locked --release -p fg-control -p fg-proxy -p fg-cli -p fg-diff
	PYTHONDONTWRITEBYTECODE=1 python3 test/p7/run.py "$(ENGINE)"

p7-gate:
	FG_GATE_BUILD_REVISION="$$(git rev-parse HEAD)" $(CARGO) build --locked --release -p fg-control -p fg-proxy -p fg-cli -p fg-diff
	PYTHONDONTWRITEBYTECODE=1 python3 test/p7/gate.py "$(PROFILE)" "$(ENGINE)"
