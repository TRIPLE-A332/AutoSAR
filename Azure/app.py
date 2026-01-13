import os
import json
from datetime import datetime

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv

from langchain_openai import AzureChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from azure.storage.blob import BlobServiceClient

# -------------------- ENV SETUP --------------------
load_dotenv()

# -------------------- FASTAPI APP --------------------
app = FastAPI(title="AutoSAR – AML Narrative Generator")

# -------------------- SENSITIVE KEYS --------------------
SENSITIVE_KEYS = {
    "account_id",
    "account_number",
    "card_number",
    "ssn",
    "email",
    "ip_address",
    "url",
    "domain",
    "name",
    "linked_accounts",
    "transaction_id",
}

# -------------------- JSON REDACTION --------------------
def local_guardrail_redact_json(raw_json: str) -> str:
    data = json.loads(raw_json)

    def redact(obj):
        if isinstance(obj, dict):
            result = {}
            for k, v in obj.items():
                key_lower = k.lower()
                if key_lower in SENSITIVE_KEYS:
                    result[k] = f"[{k.upper()}_REDACTED]"
                else:
                    result[k] = redact(v)
            return result
        elif isinstance(obj, list):
            return [redact(x) for x in obj]
        elif isinstance(obj, str):
            #redact any embedded account numbers or emails inside strings
            return obj
        else:
            return obj

    return json.dumps(redact(data), indent=2)



# -------------------- LLM INITIALIZATION (ONCE) --------------------
llm = AzureChatOpenAI(
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
    api_key=os.getenv("AZURE_OPENAI_API_KEY"),
    api_version="2024-12-01-preview",
    azure_deployment="gpt-4.1-mini",
    temperature=0.3
)

prompt = ChatPromptTemplate.from_messages([
    ("system",
     "You are an AML compliance analyst writing lawful SAR summaries. "
     "Output must be plain English with no markdown and no line breaks. "
     "Return a single continuous paragraph. "
     "If a field value is redacted and shown as [KEY_REDACTED],"
     "write it exactly as [KEY_REDACTED] in the narrative."
     "Do NOT replace or reword placeholders. "
     "Use ONLY the information provided. "
     "Do NOT invent names, entities, or facts. "
     "If information is missing, state 'Information unavailable.'"),
    ("user",
     "Write a concise SAR narrative (<=300 words) from this JSON. "
     "Include who, what, when, where, how, why, detection source, and amounts. "
     "End with one sentence stating the report date, amount (if any), and main entity.\n\n{data}")
])

chain = prompt | llm

# -------------------- AZURE BLOB STORAGE --------------------
def save_to_azure_blob_json(filename: str, data: dict):
    conn_str = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
    blob_service_client = BlobServiceClient.from_connection_string(conn_str)

    container_name = "sarnarratives"
    try:
        blob_service_client.create_container(container_name)
    except Exception as e:
        
        if "ContainerAlreadyExists" not in str(e):
            raise
    
    blob_client = blob_service_client.get_blob_client(
        container="sarnarratives",
        blob=filename
    )

    blob_client.upload_blob(
        json.dumps(data, indent=2),
        overwrite=True
    )

# -------------------- API SCHEMAS --------------------
class SARRequest(BaseModel):
    transaction: dict

# -------------------- API ENDPOINT --------------------

@app.post("/generate-and-store")
def generate_and_store(req: SARRequest):
    try:
        # Redact sensitive data
        raw_json = json.dumps(req.transaction)
        safe_json = local_guardrail_redact_json(raw_json)
        
        # Generate narrative
        response = chain.invoke({"data": safe_json})

        # Prepare output
        sar_output = {
            "narrative": response.content,
            "redacted_input": safe_json,
            "generated_at": datetime.utcnow().isoformat(),
            "model": "gpt-4.1-mini"
        }

        # Store to Azure Blob
        filename = f"sar_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        save_to_azure_blob_json(filename, sar_output)

        return {
            "status": "stored",
            "filename": filename,
            "narrative": sar_output["narrative"]
        }
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
