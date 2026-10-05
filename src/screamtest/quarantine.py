"""Reversible quarantine: every action is generated together with its undo.

M0 only emits the plan (dry run). The executor that applies it will run under a
separate, narrowly scoped IAM role that no LLM-facing component can reach.
"""

from __future__ import annotations

import json
from datetime import datetime

from .models import QuarantineAction

POLICY_NAME = "screamtest-quarantine"

DENY_ALL = {
    "Version": "2012-10-17",
    "Statement": [{"Sid": "ScreamtestQuarantine", "Effect": "Deny", "Action": "*", "Resource": "*"}],
}


def plan_quarantine(role: str, at: datetime) -> QuarantineAction:
    return QuarantineAction(
        role=role,
        apply=[
            {"api": "iam:PutRolePolicy", "RoleName": role, "PolicyName": POLICY_NAME,
             "PolicyDocument": json.dumps(DENY_ALL)},
            {"api": "iam:TagRole", "RoleName": role,
             "Tags": [{"Key": "screamtest:quarantined-at", "Value": at.isoformat()}]},
        ],
        undo=[
            {"api": "iam:DeleteRolePolicy", "RoleName": role, "PolicyName": POLICY_NAME},
            {"api": "iam:UntagRole", "RoleName": role, "TagKeys": ["screamtest:quarantined-at"]},
        ],
    )
