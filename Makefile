PYTHON ?= python3
IMAGE ?= cyber-llm-agent:latest

.PHONY: install install-web install-lab test test-ci test-web benchmark benchmark-real-llm benchmark-report lint run-api run-web run-lab smoke smoke-checklist ci validate-traces release-gate docker-build docker-run test-memory rag-build-index rag-verify rag-benchmark

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
	$(PYTHON) scripts/run_benchmark.py --mode $${BENCHMARK_MODE:-offline} --agent-mode $${BENCHMARK_AGENT_MODE:-g1} --provider $${BENCHMARK_PROVIDER:-openrouter} --dataset $${BENCHMARK_DATASET:-data/benchmarks/threat_cases.json} --output-dir $${BENCHMARK_OUTPUT_DIR:-data/benchmarks/results}

# Real OpenAI + tools (G1/G2). Needs OPENAI_API_KEY, OTX_API_KEY; Pinecone if ENABLE_RAG=true.
# Override budget: BENCHMARK_MAX_RUNTIME_SECONDS=300 make benchmark-real-llm
benchmark-real-llm:
	MAX_RUNTIME_SECONDS=$${BENCHMARK_MAX_RUNTIME_SECONDS:-180} $(PYTHON) scripts/run_benchmark.py --mode real-llm --agent-mode $${BENCHMARK_AGENT_MODE:-g1} --provider $${BENCHMARK_PROVIDER:-openai} --dataset $${BENCHMARK_DATASET:-data/benchmarks/threat_cases.json} --output-dir $${BENCHMARK_OUTPUT_DIR:-data/benchmarks/results}

benchmark-report:
	$(PYTHON) scripts/run_benchmark.py --output-dir $${BENCHMARK_OUTPUT_DIR:-data/benchmarks/results} --report-from-latest

lint:
	$(PYTHON) -m py_compile src/agents/g1/*.py src/agents/g2/*.py src/agents/shared/*.py services/api/*.py
	$(PYTHON) -m compileall -q src/rag src/tools/rag_tools.py

rag-build-index:
	$(PYTHON) scripts/rag_build_index.py

rag-verify:
	$(PYTHON) scripts/rag_verify_index.py

rag-benchmark:
	$(PYTHON) scripts/rag_benchmark.py

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
