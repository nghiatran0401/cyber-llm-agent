PYTHON ?= python
IMAGE ?= cyber-llm-agent:latest

.PHONY: install install-web test test-web lint run-api run-web smoke smoke-checklist ci docker-build docker-run

install:
	$(PYTHON) -m pip install -r requirements.txt

install-web:
	npm --prefix apps/web install

test:
	pytest -q

test-web:
	npm --prefix apps/web run test

lint:
	$(PYTHON) -m py_compile src/agents/g1/simple_agent.py src/agents/g2/multiagent_system.py services/api/*.py

ci: lint test smoke

run-api:
	uvicorn services.api.main:app --host 127.0.0.1 --port 8000 --reload

run-web:
	npm --prefix apps/web run dev

smoke:
	$(PYTHON) -m py_compile src/agents/g1/*.py src/agents/g2/*.py services/api/*.py
	pytest -q tests/unit/test_memory_week4.py tests/unit/test_multiagent_week6.py

smoke-checklist:
	$(PYTHON) scripts/smoke_checklist.py

docker-build:
	docker build -t $(IMAGE) .

docker-run:
	docker run --rm -p 8000:8000 --env-file .env $(IMAGE)
