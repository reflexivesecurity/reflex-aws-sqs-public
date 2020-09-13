""" Module for SqsPublic """

import json
import os

import boto3
from reflex_core import AWSRule, subscription_confirmation
# from .policy_evaluator import PolicyEvaluator


class SqsPublic(AWSRule):
    """
    Reflex Rule to detect publicly accessible SQS queues
    """

    client = boto3.client("sqs")

    def __init__(self, event):
        super().__init__(event)

    def extract_event_data(self, event):
        """ Extract required event data """
        self.queue_url = event["detail"]["requestParameters"]["queueUrl"]
        self.queue_policy = self.get_queue_policy(self.queue_url)

    def resource_compliant(self):
        """
        Determine if the resource is compliant with your rule.

        Return True if it is compliant, and False if it is not.
        """
        policy_evaluator = PolicyEvaluator(self.queue_policy)
        return policy_evaluator.policy_is_compliant()

    def remediate(self):
        """
        Fix the non-compliant resource so it conforms to the rule
        """
        # TODO: This is possible to remove the policy statements by "Sid" with sqs.remove_permission()
        pass

    def get_remediation_message(self):
        """ Returns a message about the remediation action that occurred """
        return f"The SQS Policy is too permissive. You are either using Principal: *, or you have no condition specified.\n Queue Url: {self.queue_url}"

    def get_queue_policy(self, queue_url):
        response = self.client.get_queue_attributes(
            QueueUrl=queue_url,
            AttributeNames=['Policy']
        )
        queue_policy = response['Attributes']['Policy']

        return queue_policy


def lambda_handler(event, _):
    """ Handles the incoming event """
    print(event)
    if subscription_confirmation.is_subscription_confirmation(event):
        subscription_confirmation.confirm_subscription(event)
        return
    rule = SqsPublic(json.loads(event["Records"][0]["body"]))
    rule.run_compliance_rule()


class PolicyEvaluator(object):

    def __init__(self, policy_json):
        self.policy_json = policy_json
        self.get_policy_dict()

    def get_policy_dict(self):
        self.policy_dict = json.loads(self.policy_json)
        return self.policy_dict

    def get_statements(self):
        return self.policy_dict.get("Statement", None)

    @staticmethod
    def statement_has_principal_star_or_blank(statement):
        principal = statement.get("Principal", None)
        return bool("" == principal or "*" == principal)

    @staticmethod
    def statement_has_condition(statement):
        condition = statement.get("Condition", {})
        return bool( len(condition.keys()) > 0)

    def statement_is_compliant(self, statement):
        return bool(
            (not self.statement_has_principal_star_or_blank(statement))
            or self.statement_has_condition(statement)
        )

    def policy_is_compliant(self):
        compliant = True
        for statement in self.get_statements():
            compliant &= self.statement_is_compliant(statement)
        return compliant
