#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from http.server import BaseHTTPRequestHandler, HTTPServer
from scoring import get_interests, get_score
import re

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}

###--------------------------------------------- Create Descriptors ------------------------------------------


class Fields:
    __metaclass__ = abc.ABCMeta

    def __init__(self, required, nullable=None):
        self.required = required
        self.nullable = nullable if nullable else False

    def __set_name__(self, owner, name):
        self.public_name = name
        self.private_name = '_' + name

    def __get__(self, instance, cls):
        return getattr(instance, self.private_name)

    def __set__(self, instance, value):
        if self.required and value is None:
            raise ValueError('{} is a required field'.format(self.public_name))
        self.validate(value)
        setattr(instance, self.private_name, value)

    @abc.abstractmethod
    def validate(self, value):
        pass


class CharField(Fields):
    def validate(self, value):
        if not isinstance(value, str) and value is not None:
            raise TypeError('{} must be a string'.format(self.public_name))


class ArgumentsField(Fields):
    def validate(self, value):
        if not isinstance(value, dict):
            raise TypeError('{} must be a dictionary'.format(self.public_name))


class EmailField(Fields):
    def validate(self, value):
        email_ = r'\w+@[a-z]+\.[a-z]+'
        email_templ = re.compile(email_)
        if value is not None:
            if not isinstance(value, str):
                raise TypeError('{} must be a string'.format(self.public_name))
            elif not email_templ.fullmatch(value):
                raise ValueError('{} is not an email address'.format(self.public_name))


class PhoneField(Fields):
    def validate(self, value):
        phone_ = r'7\d{10}'
        phone_templ = re.compile(phone_)
        if value is not None:
            if not isinstance(value, (str, int)):
                raise TypeError('{} must be a string or an integer'.format(self.public_name))
            elif ((isinstance(value, str) and not phone_templ.fullmatch(value)) or
                  (isinstance(value, int) and value//7e+10 < 1.)):
                raise ValueError('{} is not a phone number, should start with 7'.format(self.public_name))


class DateField(Fields):
    def validate(self, value):
        if value is not None:
            try:
                datetime.datetime.strptime(value, '%d.%m.%Y')
            except ValueError:
                raise ValueError('{} must be a correct data, in format DD.MM.YYYY'.format(self.public_name))


class BirthDayField(Fields):
    def validate(self, value):
        now = datetime.datetime.today()
        if value is not None:
            try:
                data_tmp = datetime.datetime.strptime(value, '%d.%m.%Y')
            except ValueError:
                raise TypeError('{} must be a correct data, in format DD.MM.YYYY'.format(self.public_name))
            else:
                if (now - data_tmp).days / 365 > 70:
                    raise ValueError('{} is older than 70 yeahs'.format(self.public_name))


class GenderField(Fields):
    def validate(self, value):
        if value is not None:
            if not isinstance(value, int):
                raise TypeError('{} must be an integer'.format(self.public_name))
            elif value not in [0, 1, 2]:
                raise ValueError('{} must be one of [0, 1, 2]'.format(self.public_name))


class ClientIDsField(Fields):
    def validate(self, value):
        if not isinstance(value, list):
            raise TypeError('{} must be a list'.format(self.public_name))
        if len(value) == 0:
            raise ValueError('{} must be non empty list'.format(self.public_name))
        elif sum([isinstance(i, (int, float)) for i in value]) != len(value):
            raise ValueError('{} must be a list of numbers'.format(self.public_name))


###------------------------------------------ Create API -------------------------------------------------

class ClientsInterestsRequest(object):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def __init__(
            self,
            client_ids=None,
            date=None):
        self.client_ids = client_ids
        self.date = date


class OnlineScoreRequest(object):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(
            self,
            first_name=None,
            last_name=None,
            email=None,
            phone=None,
            birthday=None,
            gender=None):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.phone = phone
        self.birthday = birthday
        self.gender = gender


class MethodRequest(object):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    def __init__(
            self,
            login=None,
            token=None,
            arguments=None,
            method=None,
            account=None):
        self.login = login
        self.token = token
        self.arguments = arguments
        self.method = method
        self.account = account

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


###--------------------------------------------------- Methcds ---------------------------------------------------

def check_auth(request):
    """
    function check the authority and than check that the hashed login corresponds to the token that has been sent
    Takes request event
    :return bool
    """
    if request.is_admin:
        digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode('utf-8')).hexdigest()
    else:
        digest = hashlib.sha512((request.account + request.login + SALT).encode('utf-8')).hexdigest()
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


def method_apply(request):
    """
    function tries to evaluate scoring or interest with check of variables validity first
    :return code, result from get_interest_response or get_score_response functions or default response
    """
    method, arguments = request.method, request.arguments
    context = {}
    available_methods = {
        "online_score": (OnlineScoreRequest, get_score_response),
        "clients_interests": (ClientsInterestsRequest, get_interest_response)
    }
    try:
        local_request = available_methods[method][0](**arguments)
        notnullable = [k for k, v in local_request.__dict__.items() if v is not None]
        if (('_client_ids' in notnullable) or
            ('_phone' in notnullable and '_email' in notnullable) or
            ('_first_name' in notnullable and '_last_name' in notnullable) or
            ('_gender' in notnullable and '_birthday' in notnullable)):
            pass
        else:
            raise ValueError('Arguments dictionary does not have required keys')
    except (TypeError, ValueError) as e:
        logging.info("Validation error: %s" % e)
        code = INVALID_REQUEST
        response = getattr(e, 'message', str(e))
    except KeyError as e:
        logging.info("Attribute method is not valid: %s" % e)
        code, response = INVALID_REQUEST, ERRORS[INVALID_REQUEST]
    else:
        code = OK
        response, context = available_methods[method][1](request, local_request)
    logging.info(response)
    return code, response, context


def method_handler(request, ctx):
    """
    function check the validity of request's attributes, if correct return result from function method_apply
    :param request: POST request
    :param ctx: logging dictionary
    :return: response and code, is the request successful or not
    """
    request_body, request_header = request['body'], request['headers']
    try:
        request_obj = MethodRequest(**request_body)
    except (TypeError, ValueError) as e:
        logging.info("Validation had not passed: %s" % getattr(e, 'message', str(e)))
        code, response = INVALID_REQUEST, ERRORS[INVALID_REQUEST]
    else:
        if not check_auth(request_obj):
            code, response = FORBIDDEN, 'Authorization is failed'
            logging.info("Authorization is failed")
        else:
            code, response, context = method_apply(request_obj)
            ctx.update(context)
    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        data_string = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
