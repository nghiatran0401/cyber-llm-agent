PYTHON ?= python
IMAGE ?= cyber-llm-agent:latest

.PHONY: install test lint run-streamlit smoke ci docker-build docker-run

install:
	$(PYTHON) -m pip install -r requirements.txt

test:
	pytest -q

lint:
	$(PYTHON) -m py_compile ui/streamlit/app.py src/agents/g1/simple_agent.py src/agents/g2/multiagent_system.py

ci: lint test smoke

run-streamlit:
	streamlit run ui/streamlit/app.py --server.address 127.0.0.1 --server.port 8501

smoke:
	$(PYTHON) -m py_compile ui/streamlit/app.py src/agents/g1/*.py src/agents/g2/*.py
	pytest -q tests/unit/test_memory_week4.py tests/unit/test_multiagent_week6.py

docker-build:
	docker build -t $(IMAGE) .

docker-run:
	docker run --rm -p 8501:8501 --env-file .env $(IMAGE)
