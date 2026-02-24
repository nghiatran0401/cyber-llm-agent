# CyberSecurity LLM Agents Project

## Project Overview

This project implements an LLM-powered cybersecurity support agent (G1) and multiagent system (G2) that diagnoses issues, detects/predicts cyber attacks, and integrates CTI reports for proactive defense.

**Course**: COS30018 - Intelligent Systems  
**Duration**: Weeks 3-12 (10 weeks)  
**Target**: High Distinction (HD)

## Setup

### Prerequisites

- Python 3.10+ (Python 3.13.2 recommended)
- Conda environment (ml)
- OpenAI API key
- Git & GitHub account

### Installation

1. **Clone repository** (if applicable)
   ```bash
   git clone <your-repo-url>
   cd ai-agent
   ```

2. **Activate conda environment**
   ```bash
   conda activate ml
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up environment variables**
   ```bash
   cp .env.example .env
   # Edit .env and add your API keys
   ```

5. **Verify installation**
   ```bash
   python -c "from langchain_openai import ChatOpenAI; print('LangChain OK')"
   python -c "import streamlit; print('Streamlit OK')"
   ```

6. **Run tests** (when available)
   ```bash
   pytest tests/
   ```

## Project Structure

```
cyber-llm-agent/
├── src/
│   ├── agents/
│   │   ├── g1/                 # Single-agent modules (base, simple, memory)
│   │   ├── g2/                 # Multiagent modules (roles, workflow)
│   │   └── *.py                # Backward-compatible import wrappers
│   ├── tools/                  # Security tools (log parser, CTI fetch)
│   ├── sandbox/                # OWASP sandbox event generation/logging
│   ├── utils/                  # Memory, sessions, evaluation, logging
│   └── config/                 # Configuration and model routing policy
├── ui/
│   ├── streamlit/app.py        # Primary customer-facing UI
│   └── gradio/app.py           # Alternative UI (optional)
├── tests/
│   ├── unit/                   # Unit tests
│   └── integration/            # Integration tests
├── data/
│   └── benchmarks/             # Threat case datasets
├── prompts/                    # Prompt templates (versioned)
├── requirements.txt
├── plan.md
└── README.md
```

## Usage

### Running the Single Agent (G1)

```bash
python -m src.agents.g1.simple_agent
```

### Running the Multiagent System (G2)

```bash
python -m src.agents.g2.multiagent_system
```

### Running the UI

```bash
streamlit run ui/streamlit/app.py
```

## Development Workflow

1. **Week 1-2**: Foundations & Setup (Phase 1) ✅
2. **Week 3-5**: Single Autonomous Agent (G1)
3. **Week 6-8**: Multiagent System & UI (G2)
4. **Week 9-10**: Evaluation & Analysis
5. **Week 11-12**: Documentation & Submission

## Key Features

- **G1 (Single Agent)**: Log analysis, threat detection, CTI integration
- **G2 (Multiagent)**: Specialized agents (LogAnalyzer, ThreatPredictor, IncidentResponder, Orchestrator)
- **UI**: Streamlit/Gradio web interface
- **Deployment**: HuggingFace Spaces (cloud deployment)

## Contributing

See `plan.md` for detailed project plan and development guidelines.

## License

[Add license information]

## Contact

[Add team contact information]

