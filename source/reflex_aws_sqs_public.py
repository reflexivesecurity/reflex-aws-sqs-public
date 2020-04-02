""" Module for SqsPublic """

import json
import os

import boto3
from reflex_core import AWSRule
from .policy_evaluator import PolicyEvaluator


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
    rule = SqsPublic(json.loads(event["Records"][0]["body"]))
    rule.run_compliance_rule()
