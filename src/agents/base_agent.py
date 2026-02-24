""" 
Purpose: Basic agent without tools
What it does:
- Connects to OpenAI LLM
- Analyzes single log entries
- Returns severity, threat type, and recommendations
"""
import os
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI
from langchain_core.prompts import PromptTemplate
from src.config.settings import Settings
from src.utils.logger import setup_logger

load_dotenv()

logger = setup_logger(__name__)


class CyberSecurityAgent:

    def __init__(self, model_name: str = None, temperature: float = None):
        try:
            Settings.validate()
        except ValueError as e:
            logger.error(f"Configuration error: {e}")
            raise
        
        self.llm = ChatOpenAI(
            model=model_name or Settings.MODEL_NAME,
            temperature=temperature if temperature is not None else Settings.TEMPERATURE,
            openai_api_key=Settings.OPENAI_API_KEY
        )
        logger.info(f"Initialized CyberSecurityAgent with model: {self.llm.model_name}")
    
    def analyze_log(self, log_entry: str) -> str:
        """Analyze a single security log entry."""
        if not log_entry or not log_entry.strip():
            logger.warning("Empty log entry provided")
            return "Error: Empty log entry provided."
        
        try:
            prompt = PromptTemplate(
                input_variables=["log"],
                template="""You are a cybersecurity expert. Analyze this security log and identify:
1. Severity level (low/medium/high/critical)
2. Type of threat (if any)
3. Recommended action

Log: {log}

Analysis:"""
            )
            chain = prompt | self.llm
            result = chain.invoke({"log": log_entry})
            
            if hasattr(result, 'content'):
                analysis = result.content
            else:
                analysis = str(result)
            
            logger.info(f"Log analysis completed. Response length: {len(analysis)}")
            return analysis
            
        except Exception as e:
            error_msg = f"Error analyzing log: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"


# Test
if __name__ == "__main__":
    try:
        agent = CyberSecurityAgent()
        test_log = "Failed login attempt from IP 192.168.1.100 after 5 tries"
        print(f"\nInput: {test_log}")
        print("\nAnalysis:")
        result = agent.analyze_log(test_log)
        print(result)
    except Exception as e:
        print(f"Error: {e}")
        print("Make sure OPENAI_API_KEY is set in your .env file")

