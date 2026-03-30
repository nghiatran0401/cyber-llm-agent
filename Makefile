PYTHON ?= python
IMAGE ?= cyber-llm-agent:latest

.PHONY: install install-web install-lab test test-ci test-web benchmark benchmark-report lint run-api run-web run-lab smoke smoke-checklist ci clean docker-build docker-run docker-up docker-down docker-reset docker-logs

install:
	$(PYTHON) -m pip install -r requirements.txt

install-web:
	npm --prefix apps/web install

install-lab:
	npm --prefix apps/vuln-lab install

test:
	PYTHONPATH=. pytest -q

test-ci:
	PYTHONPATH=. pytest -q --ignore=tests/unit/test_multiagent.py --ignore=tests/unit/test_rag_tools.py --ignore=tests/unit/test_service_g1_phase2.py --ignore=tests/unit/test_tools.py --ignore=tests/integration/test_agent_flow.py

test-web:
	npm --prefix apps/web run test

benchmark:
	$(PYTHON) -m src.benchmarking.runner --mode $${BENCHMARK_MODE:-offline} --agent-mode $${BENCHMARK_AGENT_MODE:-g1} --provider $${BENCHMARK_PROVIDER:-openai} --dataset $${BENCHMARK_DATASET:-data/benchmarks/threat_cases.json} --output-dir $${BENCHMARK_OUTPUT_DIR:-data/benchmarks/results}

benchmark-report:
	$(PYTHON) -m src.benchmarking.runner --output-dir $${BENCHMARK_OUTPUT_DIR:-data/benchmarks/results} --report-from-latest

lint:
	$(PYTHON) -m py_compile src/agents/g1/*.py src/agents/g2/*.py src/agents/shared/*.py services/api/*.py

ci: lint test-ci benchmark smoke test-web

clean:
	rm -rf node_modules
	rm -rf apps/web/node_modules
	rm -rf apps/vuln-lab/node_modules
	rm -rf apps/web/.next
	rm -f .DS_Store apps/web/.DS_Store apps/vuln-lab/.DS_Store

run-api:
	uvicorn services.api.main:app --host 127.0.0.1 --port 8000 --reload

run-web:
	npm --prefix apps/web run dev

run-lab:
	npm --prefix apps/vuln-lab run dev

smoke:
	$(PYTHON) -m py_compile src/agents/g1/*.py src/agents/g2/*.py services/api/*.py
	PYTHONPATH=. pytest -q tests/unit/test_memory.py

smoke-checklist:
	$(PYTHON) scripts/smoke_checklist.py

docker-build:
	docker build -t $(IMAGE) .

docker-run:
	docker run --rm -p 8000:8000 --env-file .env $(IMAGE)

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down --remove-orphans

docker-reset:
	docker compose down -v --remove-orphans

docker-logs:
	docker compose logs -f
