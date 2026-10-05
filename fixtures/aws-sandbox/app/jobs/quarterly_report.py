"""Quarterly revenue report. Triggered by finance on the first day of each quarter."""

import boto3

REPORT_ROLE = "arn:aws:iam::111122223333:role/reports-quarterly-role"


def run() -> None:
    creds = boto3.client("sts").assume_role(
        RoleArn=REPORT_ROLE, RoleSessionName="quarterly-report"
    )["Credentials"]
    athena = boto3.client(
        "athena",
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
    athena.start_query_execution(QueryString="SELECT * FROM revenue_q")
