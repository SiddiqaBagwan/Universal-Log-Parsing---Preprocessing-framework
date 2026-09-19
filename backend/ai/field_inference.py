import json
import os

from dotenv import load_dotenv

load_dotenv()

from google import genai
from pydantic import BaseModel


class FieldMapping(BaseModel):
    source_field: str
    target_field: str
    confidence: float
    reason: str


class MappingSuggestion(BaseModel):
    mappings: list[FieldMapping]


def infer_field_mapping(log_sample: str) -> dict:
    """
    Use Gemini to infer how fields from an unknown log
    map to the LogNexus normalized event schema.
    """

    api_key = os.getenv("GEMINI_API_KEY")

    if not api_key:
        raise RuntimeError("GEMINI_API_KEY is not configured.")

    client = genai.Client(api_key=api_key)

    target_schema = [
        "event_id",
        "timestamp",
        "source",
        "device",
        "event_type",
        "severity",
        "source_ip",
        "source_port",
        "destination_ip",
        "destination_port",
        "user_id",
        "user_name",
        "action",
        "outcome",
        "message",
        "extra_data",
    ]

    prompt = f"""
You are a log normalization assistant for LogNexus.

Analyze the following unknown log sample and infer the STRUCTURE
of the log.

UNKNOWN LOG:
{log_sample}

Map each field/position in the unknown log to the most appropriate
LogNexus normalized event field.

AVAILABLE LOGNEXUS FIELDS:
{json.dumps(target_schema, indent=2)}

IMPORTANT:

1. Identify the meaning of each field, not merely its example value.

2. DO NOT use actual sample values as source_field names.

3. For logs with explicit field names, use the actual field name.
   Example:
   src_ip -> source_ip
   dst_ip -> destination_ip
   username -> user_name

4. For positional/unlabelled logs, identify fields by their position.
   Use names such as:
   field_1
   field_2
   field_3
   etc.

5. Example:
   If the log is:
   timestamp firewall01 ALLOW 10.0.0.1 10.0.0.2 TCP

   return mappings conceptually like:
   field_1 -> timestamp
   field_2 -> device
   field_3 -> action
   field_4 -> source_ip
   field_5 -> destination_ip
   field_6 -> extra_data

6. Do not invent fields that are not present.

7. Do not guess sensitive values.

8. Use confidence between 0 and 1.

9. Only suggest mappings reasonably supported by the sample.

10. Preserve source-specific fields through extra_data when
    there is no suitable normalized field.

11. Return ONLY the structured mapping.

12. The destination field key MUST be named "target_field".
    NEVER use "normalized_field".

13. Return the mapping using exactly this JSON structure:
13. Return the mapping using exactly this JSON structure:
{{
  "mappings": [
    {{
      "source_field": "field_1",
      "target_field": "timestamp",
      "confidence": 1.0,
      "reason": "The first field represents the event timestamp."
    }}
  ]
}}
"""

    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
        config={
            "response_mime_type": "application/json",
        },
    )

    result = json.loads(response.text)

    return result

    


if __name__ == "__main__":
    sample_log = """
    2026-09-15T19:45:16Z
    firewall01
    ALLOW
    10.99.160.25
    10.99.160.81
    UDP
    60807
    53
    """

    result = infer_field_mapping(sample_log)

    print(json.dumps(result, indent=2))