import json


class PolicyEvaluator(object):

    def __init__(self, policy_json):
        self.policy_json = policy_json
        self.get_policy_dict()

    def get_policy_dict(self):
        self.policy_dict = json.loads(self.policy_json)
        return self.policy_dict

    def get_statements(self):
        return self.policy_dict["Statement", None]

    @staticmethod
    def statement_has_principal_star_or_blank(statement):
        principal = statement.get("Principal", None)
        return bool("" == principal or "*" == principal)

    @staticmethod
    def statement_has_condition(statement):
        condition = statement.get("Condition", None)
        return bool(
            condition.keys() > 0
        )

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
