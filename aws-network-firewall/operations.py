""" Copyright start
  Copyright (C) 2008 - 2021 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import boto3, requests, json
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('aws-network-firewall')

TEMP_CRED_ENDPOINT = 'http://169.254.169.254/latest/meta-data/iam/security-credentials/{}'


class AWSNetworkFirewall(object):
    def __init__(self, config):
        self.config_type = config.get('config_type')
        self.aws_region = config.get('aws_region')
        self.aws_access_key = config.get('access_key')
        self.aws_secret_access_key = config.get('secret_key')
        self.aws_iam_role = config.get('aws_iam_role')
        self.verify_ssl = config.get('verify_ssl')

    def get_temp_credentials(self):
        try:
            url = TEMP_CRED_ENDPOINT.format(self.aws_iam_role)
            resp = requests.get(url=url, verify=self.verify_ssl)
            if resp.ok:
                cred = json.loads(resp.text)
                return cred
            else:
                logger.error(str(resp.text))
                raise ConnectorError("Unable to validate the credentials")
        except Exception as Err:
            logger.exception(Err)
            raise ConnectorError(Err)

    def get_session(self, params):
        try:
            assume_role = params.get("assume_role", False)
            if self.config_type == "IAM Role":
                if not assume_role:
                    raise ConnectorError("Please Assume a Role to execute actions")

                aws_region = params.get('aws_region')
                temp_cred = self.get_temp_credentials()
                aws_session = self.assume_a_role(temp_cred, params, aws_region)
                return aws_session
            else:
                if assume_role:
                    data = {
                        "AccessKeyId": self.aws_access_key,
                        "SecretAccessKey": self.aws_secret_access_key,
                        "Token": None
                    }
                    aws_session = self.assume_a_role(data, params, self.aws_region)
                else:
                    aws_session = boto3.session.Session(region_name=self.aws_region,
                                                        aws_access_key_id=self.aws_access_key,
                                                        aws_secret_access_key=self.aws_secret_access_key)
                return aws_session
        except Exception as Err:
            logger.exception(Err)
            raise ConnectorError(Err)

    def assume_a_role(self, temp_cred, params, aws_region):
        try:
            client = boto3.client('sts', region_name=aws_region, aws_access_key_id=temp_cred.get('AccessKeyId'),
                                  aws_secret_access_key=temp_cred.get('SecretAccessKey'),
                                  aws_session_token=temp_cred.get('Token'))
            role_arn = params.get('role_arn')
            session_name = str(params.get('session_name'))
            response = client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            aws_region2 = params.get('aws_region')
            aws_session = boto3.session.Session(region_name=aws_region2,
                                                aws_access_key_id=response['Credentials']['AccessKeyId'],
                                                aws_secret_access_key=response['Credentials']['SecretAccessKey'],
                                                aws_session_token=response['Credentials']['SessionToken'])
            return aws_session
        except Exception as Err:
            logger.exception(Err)
            raise ConnectorError(Err)

    def get_aws_client(self, params, service='network-firewall'):
        try:
            aws_session = self.get_session(params)
            return aws_session.client(service, verify=self.verify_ssl)
        except Exception as Err:
            logger.exception(Err)
            raise ConnectorError(Err)


def remove_extra_param(params):
    params.pop('aws_region', None)
    params.pop('assume_role', None)
    params.pop('session_name', None)
    params.pop('role_arn', None)
    params = {k: v for k, v in params.items() if v is not None and v != ''}
    return params


def get_list_params(param):
    if param and isinstance(param, list):
        return param
    if param and isinstance(param, str):
        return param.split(',')
    return []


def get_list_tags(tags):
    if isinstance(tags, dict):
        list_tags = [tags]
    else:
        list_tags = get_list_params(tags)
    return list_tags


def get_associate_firewall_policy(config, params):
    try:
        aws_nw = AWSNetworkFirewall(config)
        aws_client = aws_nw.get_aws_client(params)
        kwargs = remove_extra_param(params)
        return aws_client.associate_firewall_policy(**kwargs)
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def get_associate_subnets(config, params):
    try:
        aws_nw = AWSNetworkFirewall(config)
        subnet_ids = get_list_params(params.get('SubnetMappings'))
        params['SubnetMappings'] = [{'SubnetId': id} for id in subnet_ids]
        aws_client = aws_nw.get_aws_client(params)
        kwargs = remove_extra_param(params)
        return aws_client.associate_subnets(**kwargs)
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def create_firewall(config, params):
    try:
        aws_nw = AWSNetworkFirewall(config)
        aws_client = aws_nw.get_aws_client(params)
        params = remove_extra_param(params)
        subnet_ids = get_list_params(params.get('SubnetMappings'))
        params['SubnetMappings'] = [{'SubnetId': id} for id in subnet_ids]
        tags = params.get('Tags')
        params['Tags'] = get_list_tags(params.get('Tags'))
        kwargs = remove_extra_param(params)
        return aws_client.associate_subnets(**params)
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def create_firewall_policy(config, params):
    try:
        aws_nw = AWSNetworkFirewall(config)
        aws_client = aws_nw.get_aws_client(params)
        tags = get_list_tags(params.get('Tags'))
        kwargs = {
            'FirewallPolicyName': params.get('FirewallPolicyName'),
            'FirewallPolicy': params.get('firewall_policy_json'),
            'Description': params.get('Description'),
            'Tags': tags
        }
        kwargs = remove_extra_param(kwargs)
        return aws_client.create_firewall_policy(**kwargs)
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def create_rule_group(config, params):
    try:
        aws_nw = AWSNetworkFirewall(config)
        aws_client = aws_nw.get_aws_client(params)
        setting_type = params.pop('setting_type', '')
        kwargs = {
            "RuleGroupName": params.get("rule_group_name"),
            "RuleGroup": params.get('rule_group'),
            "Rules": params.get("rules"),
            "Type": params.get("type"),
            "Capacity": int(params.get("capacity")),
            "Description": params.get("description"),
            "Tags": get_list_tags(params.get("tags")),
        }
        kwargs = remove_extra_param(kwargs)
        return aws_client.create_rule_group(**kwargs)
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def delete_firewall(config, params):
    try:
        aws_nw = AWSNetworkFirewall(config)
        aws_client = aws_nw.get_aws_client(params)
        kwargs = remove_extra_param(params)
        if not kwargs:
            raise ConnectorError('You must specify the Firewall ARN or the Firewall name, and you can specify both.')
        return aws_client.delete_firewall(**kwargs)
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def delete_firewall_policy(config, params):
    try:
        aws_nw = AWSNetworkFirewall(config)
        aws_client = aws_nw.get_aws_client(params)
        kwargs = remove_extra_param(params)
        if not kwargs:
            raise ConnectorError(
                'You must specify the Firewall Policy ARN or the Firewall Policy name, and you can specify both.')
        return aws_client.delete_firewall_policy(**kwargs)
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def delete_resource_policy(config, params):
    try:
        aws_nw = AWSNetworkFirewall(config)
        aws_client = aws_nw.get_aws_client(params)
        kwargs = remove_extra_param(params)
        resp = aws_client.delete_firewall_policy(**kwargs)
        return {'status': 'successful', 'result': 'Resource policy successfully deleted'} if not resp else resp
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def delete_rule_group(config, params):
    try:
        aws_nw = AWSNetworkFirewall(config)
        aws_client = aws_nw.get_aws_client(params)
        kwargs = remove_extra_param(params)
        return aws_client.delete_rule_group(**kwargs)
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def describe_firewall(config, params):
    try:
        aws_nw = AWSNetworkFirewall(config)
        aws_client = aws_nw.get_aws_client(params)
        kwargs = remove_extra_param(params)
        return aws_client.describe_firewall(**kwargs)
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def describe_firewall_policy(config, params):
    try:
        aws_nw = AWSNetworkFirewall(config)
        aws_client = aws_nw.get_aws_client(params)
        kwargs = remove_extra_param(params)
        return aws_client.describe_firewall_policy(**kwargs)
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def describe_logging_configuration(config, params):
    try:
        aws_nw = AWSNetworkFirewall(config)
        aws_client = aws_nw.get_aws_client(params)
        kwargs = remove_extra_param(params)
        return aws_client.describe_logging_configuration(**kwargs)
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def describe_resource_policy(config, params):
    try:
        aws_nw = AWSNetworkFirewall(config)
        aws_client = aws_nw.get_aws_client(params)
        kwargs = remove_extra_param(params)
        return aws_client.describe_resource_policy(**kwargs)
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def describe_rule_group(config, params):
    try:
        aws_nw = AWSNetworkFirewall(config)
        aws_client = aws_nw.get_aws_client(params)
        kwargs = remove_extra_param(params)
        return aws_client.describe_rule_group(**kwargs)
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def disassociate_subnets(config, params):
    try:
        aws_nw = AWSNetworkFirewall(config)
        aws_client = aws_nw.get_aws_client(params)
        params['SubnetIds'] = get_list_params(params.get('SubnetIds'))
        kwargs = remove_extra_param(params)
        return aws_client.disassociate_subnets(**kwargs)
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def get_list_firewalls(config, params):
    try:
        aws_nw = AWSNetworkFirewall(config)
        aws_client = aws_nw.get_aws_client(params)
        params['VpcIds'] = get_list_params(params.get('VpcIds'))
        kwargs = remove_extra_param(params)
        return aws_client.list_firewalls(**kwargs)
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def get_list_firewall_policies(config, params):
    try:
        aws_nw = AWSNetworkFirewall(config)
        aws_client = aws_nw.get_aws_client(params)
        kwargs = remove_extra_param(params)
        return aws_client.list_firewall_policies(**kwargs)
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def get_list_rule_groups(config, params):
    try:
        aws_nw = AWSNetworkFirewall(config)
        aws_client = aws_nw.get_aws_client(params)
        kwargs = remove_extra_param(params)
        return aws_client.list_rule_groups(**kwargs)
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def get_list_tag_for_resource(config, params):
    try:
        aws_nw = AWSNetworkFirewall(config)
        aws_client = aws_nw.get_aws_client(params)
        kwargs = remove_extra_param(params)
        return aws_client.list_tags_for_resource(**kwargs)
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def tag_resource(config, params):
    try:
        aws_nw = AWSNetworkFirewall(config)
        aws_client = aws_nw.get_aws_client(params)
        params['Tags'] = get_list_tags(params.get('Tags'))
        kwargs = remove_extra_param(params)
        response = aws_client.tag_resource(**kwargs)
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def _check_health(config):
    try:
        aws_nw = AWSNetworkFirewall(config)
        config_type = aws_nw.config_type
        if config_type == "IAM Role":
            if aws_nw.get_temp_credentials():
                return True
            else:
                raise ConnectorError('Invalid Role. Please verify is the role is associated to your instance.')
        else:
            aws_client = boto3.client('network-firewall', region_name=aws_nw.aws_region,
                                      aws_access_key_id=aws_nw.aws_access_key,
                                      aws_secret_access_key=aws_nw.aws_secret_access_key)
            account_settings = aws_client.list_firewalls()
            if account_settings:
                return True
            else:
                raise ConnectorError('Invalid Region name or Aws Access Key ID or Aws Secret Access Key')
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


operations = {
    'get_associate_firewall_policy': get_associate_firewall_policy,
    'get_associate_subnets': get_associate_subnets,
    'create_firewall': create_firewall,
    'create_firewall_policy': create_firewall_policy,
    'create_rule_group': create_rule_group,
    'delete_firewall': delete_firewall,
    'delete_firewall_policy': delete_firewall_policy,
    'delete_resource_policy': delete_resource_policy,
    'delete_rule_group': delete_rule_group,
    'describe_firewall': describe_firewall,
    'describe_firewall_policy': describe_firewall_policy,
    'describe_logging_configuration': describe_logging_configuration,
    'describe_resource_policy': describe_resource_policy,
    'describe_rule_group': describe_rule_group,
    'disassociate_subnets': disassociate_subnets,
    'get_list_firewalls': get_list_firewalls,
    'get_list_firewall_policies': get_list_firewall_policies,
    'get_list_rule_groups': get_list_rule_groups,
    'get_list_tag_for_resource': get_list_tag_for_resource,
    'tag_resource': tag_resource
}
