# Security Groups Shadow Rules
For finding shadow rules on a given AWS Security Group

If there are any shadow rules in your Security Group, they will be grouped by the most open rule, 
and all shadowed rules will be added as ShadowRules for the first one.

Usage:
- Set up your AWS Credentials as Environment Variables, so Boto3 can find them automatically. 
- Execute this script using python3 and pass the sg-id as an argument

Example:

```bash
python3 shadow_rules.py sg-1234idabc
```

Output example:
```json
[
    {
        "IpRange": "137.123.4.190/28",
        "FromPort": 80,
        "ToPort": 8080,
        "IpProtocol": "tcp",
        "ShadowRules": [
            {
                "IpRange": "137.123.4.190/28",
                "FromPort": 443,
                "ToPort": 443
            },
            {
                "IpRange": "137.123.4.190/30",
                "FromPort": 80,
                "ToPort": 8080
            }
        ]
    }
]
```

## Contributing
PRs are more than welcome!