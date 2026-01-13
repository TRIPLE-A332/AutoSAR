import os
import re
import json
import hmac
import hashlib
import boto3
import botocore.config
from datetime import datetime

# ---------- Redaction utils ----------
_SECRET = os.environ.get("REDACTION_SECRET", "project-secret").encode()

def _stable_tag(kind: str, text: str, n=6) -> str:
    h = hmac.new(_SECRET, text.encode(), hashlib.sha256).hexdigest()[:n]
    return f"[{kind}:{h}]"

_email_re  = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
_card_re   = re.compile(r'\b(?:\d[ -]*?){13,19}\b')
_ssn_re    = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
_acct_re   = re.compile(r'\b\d{6,18}\b')
_ip_re     = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b')
_url_re    = re.compile(r'\bhttps?://\S+\b', re.IGNORECASE)
_domain_re = re.compile(r'\b([A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b')

def _scrub_str(s: str) -> str:
    s = _email_re.sub(lambda m: _stable_tag("EMAIL", m.group()), s)
    s = _ssn_re.sub(lambda m: _stable_tag("SSN", m.group()), s)
    s = _card_re.sub(lambda m: _stable_tag("CARD", m.group()), s)
    s = _acct_re.sub(lambda m: _stable_tag("ACCT", m.group()), s)
    s = _ip_re.sub(lambda m: _stable_tag("IP", m.group()), s)
    s = _url_re.sub(lambda m: _stable_tag("URL", m.group()), s)
    s = _domain_re.sub(lambda m: _stable_tag("DOMAIN", m.group()), s)
    return s

def scrub(obj):
    if obj is None: return None
    if isinstance(obj, str): return _scrub_str(obj)
    if isinstance(obj, (int, float, bool)): return obj
    if isinstance(obj, list): return [scrub(x) for x in obj]
    if isinstance(obj, dict): return {k: scrub(v) for k, v in obj.items()}
    return obj

ALLOWED_FIELDS = {
    "case_id", "summary", "timeline", "indicators",
    "amount_usd", "detected_by", "actions_taken", "date"
}

def allowlist(d: dict) -> dict:
    return {k: d[k] for k in d if k in ALLOWED_FIELDS}

def make_safe_payload(security_detail_json) -> str:
    data = json.loads(security_detail_json) if isinstance(security_detail_json, str) else security_detail_json
    data = allowlist(data if isinstance(data, dict) else {})
    data = scrub(data)
    return json.dumps(data, ensure_ascii=False)

# ---------- Config / clients ----------
REGION = "us-east-1"
BUCKET = "sar-output-bucket"
PROFILE_ARN = os.environ.get("INFERENCE_PROFILE_ARN")  # must be set

bedrock = boto3.client(
    "bedrock-runtime",
    region_name=REGION,
    config=botocore.config.Config(read_timeout=300, retries={'max_attempts': 3})
)
s3 = boto3.client("s3")

# ---------- Core ----------
def _normalize(text: str) -> str:
    return text.replace("\n", " ").replace("*", "").strip()

def sar_generate_using_bedrock(security_detail_json) -> str:
    safe_json = make_safe_payload(security_detail_json)

    prompt = f"""<|begin_of_text|><|start_header_id|>system<|end_header_id|>
You are an AML compliance analyst writing lawful SAR summaries. Output must be plain English with no markdown and no line breaks. Return a single, continuous paragraph.
<|eot_id|><|start_header_id|>user<|end_header_id|>
Write a concise SAR narrative (<=300 words) from this JSON. Include who, what, when, where, how, why, detection source, and amounts. End with one sentence stating the report date, amount (if any), and main entity.
JSON Input:
{safe_json}
<|eot_id|><|start_header_id|>assistant<|end_header_id|>"""

    if not PROFILE_ARN:
        raise RuntimeError("INFERENCE_PROFILE_ARN not set")

    body = {"prompt": prompt, "max_gen_len": 512, "temperature": 0.25, "top_p": 0.9}

    resp = bedrock.invoke_model(
        modelId=PROFILE_ARN,           # using profile ARN as modelId (SDK-compat hack)
        body=json.dumps(body),
        contentType="application/json",
        accept="application/json"
    )
    data = json.loads(resp["body"].read())
    return _normalize((data.get("generation") or ""))

def save_sar_to_s3(obj: dict, key: str):
    s3.put_object(
        Bucket=BUCKET,
        Key=key,
        Body=json.dumps(obj, ensure_ascii=False).encode("utf-8"),
        ContentType="application/json"
    )

def _parse_body(event):
    body = event.get("body")
    if isinstance(body, str):
        try:
            return json.loads(body)
        except Exception:
            return {}
    return body if isinstance(body, dict) else {}

def _extract_case_id(sec):
    if isinstance(sec, dict):
        return sec.get("case_id") or "NA"
    if isinstance(sec, str):
        try:
            return (json.loads(sec).get("case_id") or "NA")
        except Exception:
            return "NA"
    return "NA"

def lambda_handler(event, context):
    try:
        payload = _parse_body(event)
        sec = payload["security_detail_json"]

        narrative = sar_generate_using_bedrock(sec)
        if not narrative:
            return {"statusCode": 502, "body": json.dumps({"error": "model returned empty generation"})}

        ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        case_id = _extract_case_id(sec)
        key = f"sar-output/{case_id}/{ts}.json"

        out = {"case_id": case_id, "timestamp": ts, "model": "meta.llama3-2-1b-instruct (profile)", "narrative": narrative}
        save_sar_to_s3(out, key)

        # metadata-only log
        print(f"case={case_id} status=ok s3_key={key}")
        return {"statusCode": 200, "body": json.dumps({"s3_key": key, "narrative": narrative})}

    except KeyError as e:
        return {"statusCode": 400, "body": json.dumps({"error": f"missing field: {str(e)}"})}
    except Exception as e:
        print(f"status=error err={e}")
        return {"statusCode": 502, "body": json.dumps({"error": "internal"})}
