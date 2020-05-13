import boto3
import ipaddress
import json
import argparse


def shadow_rules(rules):
	ans = []
	for rule in rules:
		for possible_shadow in rules:
			if rule == possible_shadow: continue
			if possible_shadow['IpProtocol'] != rule['IpProtocol']: continue
			
			if int(possible_shadow['FromPort']) >= int(rule['FromPort']):
				if int(possible_shadow['ToPort']) <= int(rule['ToPort']):
					for ip_range in rule['IpRanges']:

						cidr_block = ipaddress.ip_network(ip_range['CidrIp'])
						shadowing_rule = {
							'IpRange': cidr_block.with_prefixlen,
							'FromPort': rule['FromPort'],
							'ToPort': rule['ToPort'],
							'IpProtocol': rule['IpProtocol'],
							'ShadowRules': []
						}
						for shadow_ip_range in possible_shadow['IpRanges']:
							shadow_cidr_block = ipaddress.ip_network(shadow_ip_range['CidrIp'])

							if shadow_cidr_block.subnet_of(cidr_block):
								shadowed_rule = {
									'IpRange': shadow_cidr_block.with_prefixlen,
									'FromPort': possible_shadow['FromPort'],
									'ToPort': possible_shadow['ToPort']
								}
								shadowing_rule['ShadowRules'].append(shadowed_rule)
						if len(shadowing_rule['ShadowRules']) > 0: ans.append(shadowing_rule)
		
	return ans


parser = argparse.ArgumentParser(description='Analyze shadow rules on a specific SG')
parser.add_argument('sg', type=str, help="Security Group ID to analyze")
args = parser.parse_args()

ec2 = boto3.resource('ec2')
security_group = ec2.SecurityGroup(args.sg)

shadowed_rules = security_group.ip_permissions

print(json.dumps(shadow_rules(shadowed_rules)))
