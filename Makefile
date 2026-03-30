PYTHON ?= python3
IMAGE ?= cyber-llm-agent:latest

.PHONY: install install-web install-lab test test-ci test-web benchmark benchmark-report lint run-api run-web run-lab smoke smoke-checklist ci validate-traces release-gate docker-build docker-run test-memory

install:
	$(PYTHON) -m pip install -r requirements.txt

install-web:
	cd apps/web && npm install

install-lab:
	cd apps/vuln-lab && npm install

test:
	pytest -q

test-ci:
	$(PYTHON) scripts/run_test_ci.py

test-web:
	cd apps/web && npm run test

test-memory:
	pytest -q tests/unit/test_memory.py tests/unit/test_embedding_memory.py

evaluate-memory:
	python -m src.utils.eval_memory

benchmark:
	$(PYTHON) scripts/run_benchmark.py --mode $${BENCHMARK_MODE:-offline} --agent-mode $${BENCHMARK_AGENT_MODE:-g1} --provider $${BENCHMARK_PROVIDER:-openai} --dataset $${BENCHMARK_DATASET:-data/benchmarks/threat_cases.json} --output-dir $${BENCHMARK_OUTPUT_DIR:-data/benchmarks/results}

benchmark-report:
	$(PYTHON) scripts/run_benchmark.py --output-dir $${BENCHMARK_OUTPUT_DIR:-data/benchmarks/results} --report-from-latest

lint:
	$(PYTHON) -m py_compile src/agents/g1/*.py src/agents/g2/*.py src/agents/shared/*.py services/api/*.py

ci: lint test-ci benchmark smoke test-web

run-api:
	uvicorn services.api.main:app --host 127.0.0.1 --port 8000 --reload

run-web:
	cd apps/web && npm run dev

run-lab:
	cd apps/vuln-lab && npm run dev

smoke:
	$(PYTHON) -m py_compile src/agents/g1/*.py src/agents/g2/*.py services/api/*.py
	pytest -q tests/unit/test_memory.py

smoke-checklist:
	$(PYTHON) scripts/smoke_checklist.py

validate-traces:
	$(PYTHON) scripts/validate_traces.py

release-gate:
	$(PYTHON) scripts/release_gate.py

docker-build:
	docker build -t $(IMAGE) .

docker-run:
	docker run --rm -p 8000:8000 --env-file .env $(IMAGE)
