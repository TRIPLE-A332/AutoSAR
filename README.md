# AutoSAR – Automated Suspicious Activity Report Generator

## Overview
AutoSAR is a serverless cybersecurity compliance tool that generates structured Suspicious Activity Report (SAR) narratives using **AWS Bedrock (Meta Llama 3.2 Instruct)**.
It accepts a JSON input describing a security or fraud incident, masks sensitive information, generates a narrative through the LLM, and stores the final report securely in an **Amazon S3** bucket.

## Features
- **Serverless Architecture:** Built using **AWS Lambda**, **API Gateway**, and **S3**.
- **LLM Integration:** Uses **AWS Bedrock** with **Meta Llama 3.2 1B Instruct** through inference profiles.
- **Data Masking:** Automatically redacts emails, account numbers, IPs, and domains before sending data to the model.
- **Structured Reports:** Produces concise SAR narratives following AML/Compliance standards.
- **Error Handling:** Ensures reliable execution and secure S3 storage with clean, minimal logging.

## Tech Stack
- **AWS Services:** Bedrock, Lambda, API Gateway, S3
- **Language:** Python 3.12
- **Model:** Meta Llama 3.2 1B Instruct (via inference profile)
- **Libraries:** boto3, botocore, re, hmac, hashlib, json

## Workflow
1. A POST request containing JSON data is sent to the API Gateway endpoint.
2. The Lambda function masks sensitive information using deterministic pseudonymization.
3. The sanitized payload is sent to the Bedrock LLM for SAR narrative generation.
4. The generated output is normalized and stored in S3 under a unique case ID and timestamp.

## Example Input
```json
{
  "security_detail_json": {
    "case_id": "INC-2025-1002",
    "summary": "Employee jane.doe@company.com received a phishing email...",
    "timeline": [
      {"ts": "2025-11-03T09:45:00Z", "event": "User clicked malicious link..."}
    ],
    "amount_usd": 12750,
    "detected_by": "SIEM",
    "actions_taken": ["Account disabled", "Wire reversed"]
  }
}
```

## Example Output
```json
{
  "case_id": "INC-2025-1002",
  "timestamp": "20251105T045800Z",
  "narrative": "On November 3, 2025, an employee [EMAIL:abc123] received a phishing email that led to credential theft..."
}
```

## Deployment Steps
1. Create an S3 bucket (e.g., `sar-output-bucket`).
2. Deploy the Lambda function and set the environment variable `INFERENCE_PROFILE_ARN`.
3. Configure API Gateway with a POST method pointing to the Lambda.
4. Test using Postman with the sample JSON input.

## Project Purpose
This project was developed for a **graduate-level cybersecurity and AI course** to demonstrate secure LLM integration, data masking, and automated report generation using AWS services.
