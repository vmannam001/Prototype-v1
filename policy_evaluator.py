def evaluate_request(policy, request_details):
    """
    Evaluates an access request against a loaded policy object.

    Args:
        policy (dict): The loaded policy JSON.
        request_details (dict): A dictionary containing the request's role,
                                department, resource, and action.

    Returns:
        tuple: A (decision, reason) tuple.
    """
    for rule in policy.get('rules', []):
        conditions = rule.get('conditions', {})
        
        # This checks if all conditions in a rule are met by the request.
        # The .get() method safely handles any extra keys in the request.
        if all(request_details.get(key) == value for key, value in conditions.items()):
            # If all conditions match, we return this rule's decision and stop.
            return rule['decision'], rule['reason']

    # If the loop finishes without finding a matching rule, we deny access.
    return 'denied', 'Denied: The request did not match any policy rule.'