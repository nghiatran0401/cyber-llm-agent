PYTHON ?= python

.PHONY: install test lint run-streamlit run-gradio smoke

install:
	$(PYTHON) -m pip install -r requirements.txt

test:
	pytest -q

lint:
	$(PYTHON) -m py_compile ui/streamlit/app.py src/agents/g1/simple_agent.py src/agents/g2/multiagent_system.py

run-streamlit:
	streamlit run ui/streamlit/app.py --server.address 127.0.0.1 --server.port 8501

run-gradio:
	$(PYTHON) ui/gradio/app.py

smoke:
	$(PYTHON) -m py_compile ui/streamlit/app.py src/agents/g1/*.py src/agents/g2/*.py
	pytest -q tests/unit/test_memory_week4.py tests/unit/test_multiagent_week6.py
