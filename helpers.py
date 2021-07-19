import hashlib
import datetime

from scoring import get_interests, get_score
import api


def check_auth(request):
    """
    function check the authority and than check that the hashed login corresponds to the token that has been sent
    Takes request event
    :return bool
    """
    if request.is_admin:
        digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + api.ADMIN_SALT).encode('utf-8')).hexdigest()
    else:
        digest = hashlib.sha512((request.account + request.login + api.SALT).encode('utf-8')).hexdigest()
    if digest == request.token:
        return True
    return False


def get_score_response(request, request_local):
    """
    function calculate scoring value depends on the user's authority, return score and logging context
    :return dict[str, int], dict[str, List[str]]
    """
    if request.is_admin:
        response = {'score': 42}
        context = {}
    else:
        scoring_request_dict = {k[1:]: v for k, v in request_local.__dict__.items()}
        response = {'score': get_score(**scoring_request_dict)}
        context = {'has': [k for k, v in scoring_request_dict.items() if v is not None]}
    return response, context


def get_interest_response(request, request_local):
    """
    function calculate interest, return interest and logging context
    :return dict[str, List[str]], dict[str, List[int]]
    """
    response = {str(i): get_interests(str(i)) for i in request_local.client_ids}
    context = {'nclients': len(request_local.client_ids)}
    return response, context
