# Break-glass access

Use only when SSO is down and production is impaired.

1. Retrieve the hardware MFA token from the safe.
2. Assume `breakglass-admin` from the emergency IAM user.
3. Open an incident and record every action taken.

This role is expected to show no activity. That is the point.
