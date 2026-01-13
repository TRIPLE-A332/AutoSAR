# AutoSAR – AML SAR Narrative Generator 
Video Demo - https://youtu.be/Fv7qTpV9LMY

AutoSAR is a privacy-first system for automatically generating Anti-Money Laundering (AML) Suspicious Activity Report (SAR) narratives using Large Language Models (LLMs). The project demonstrates how AI can be safely integrated into regulated financial workflows through strict redaction, prompt controls, and audit logging.

---

## Features

- Automated SAR narrative generation from structured transaction data
- Local redaction of sensitive information before LLM processing
- Deterministic placeholders for sensitive fields (no PII sent to the model)
- Azure OpenAI integration with controlled, non-hallucinating prompts
- Single-paragraph, plain-English SAR output
- Secure storage of narratives and metadata in Azure Blob Storage
- RESTful API built using FastAPI

---

## System Flow

1. Client submits transaction data as JSON
2. Sensitive fields are redacted locally using guardrails
3. Redacted data is sent to Azure OpenAI for narrative generation
4. The generated SAR narrative is returned to the client
5. Narrative, redacted input, timestamp, and model info are stored in Azure Blob Storage

---

## Architecture Overview

Client → FastAPI → Redaction Layer → Azure OpenAI → SAR Narrative → Azure Blob Storage

---

## Data Protection and Compliance

- Sensitive fields such as account numbers, names, emails, IP addresses, and linked accounts are redacted locally
- Redacted placeholders remain unchanged in the generated narrative
- The LLM is restricted to using only the provided data
- No names, entities, or facts are invented by the model
- Stored outputs support auditability and traceability

This project is for academic demonstration purposes only and is not intended for production SAR filing.

---

## Tech Stack

- Backend: FastAPI (Python)
- LLM: Azure OpenAI
- Prompting: LangChain
- Storage: Azure Blob Storage
- Environment Management: python-dotenv
- Validation: Pydantic

---

## Project Structure

autosar/Azure/
- app.py
- requirements.txt
- .env

---

## Environment Variables

Create a `.env` file with the following values:

AZURE_OPENAI_ENDPOINT=your_azure_openai_endpoint  
AZURE_OPENAI_API_KEY=your_azure_openai_api_key  
AZURE_STORAGE_CONNECTION_STRING=your_azure_storage_connection_string  

---

## Running the Application

1. Install dependencies:

pip install -r requirements.txt

2. Start the server:

uvicorn main:app --reload

3. Open API documentation:

http://127.0.0.1:8000/docs

---

## API Usage

Endpoint:  
POST /generate-and-store

Request Body Example:

{
  "transaction": {
    "account_number": "123456789",
    "amount": 25000,
    "transaction_type": "Wire Transfer",
    "date": "2024-10-15",
    "detection_source": "Transaction Monitoring System"
  }
}

Response Example:

{
  "status": "stored",
  "filename": "sar_20241015_143212.json",
  "narrative": "The account identified as [ACCOUNT_NUMBER_REDACTED] was involved in suspicious activity..."
}

---

## Learning Outcomes

- Secure use of LLMs in regulated domains
- Prompt engineering for compliance and non-hallucination
- Privacy-first data handling and redaction
- Cloud-based audit logging
- API-driven AI system design

---

## Author

Ali Abdullah Ahmad
