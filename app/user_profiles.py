import os
from datetime import datetime, timezone

import boto3
from dotenv import load_dotenv

load_dotenv()

REGION = os.getenv("AWS_REGION", "af-south-1")
TABLE_NAME = os.getenv(
    "VERYNTH_DYNAMODB_USERS_TABLE",
    "VERYNTH-Users",
)

table = boto3.resource(
    "dynamodb",
    region_name=REGION,
).Table(TABLE_NAME)


def get_or_create_user(user_id: str) -> dict:
    if not user_id:
        raise ValueError("Missing Cognito user ID")

    result = table.get_item(
        Key={"user_id": user_id},
        ConsistentRead=True,
    )

    if "Item" in result:
        return result["Item"]

    now = datetime.now(timezone.utc).isoformat()

    profile = {
        "user_id": user_id,
        "display_name": "",
        "account_type": "personal",
        "created_at": now,
        "updated_at": now,
    }

    try:
        table.put_item(
            Item=profile,
            ConditionExpression="attribute_not_exists(user_id)",
        )
        return profile
    except table.meta.client.exceptions.ConditionalCheckFailedException:
        result = table.get_item(
            Key={"user_id": user_id},
            ConsistentRead=True,
        )
        return result["Item"]
