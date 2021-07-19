#!/usr/bin/env python
# -*- coding: utf-8 -*-
import abc
import datetime
import re
import json
import logging
import uuid
from optparse import OptionParser
from http.server import BaseHTTPRequestHandler, HTTPServer

from helpers import get_score_response, get_interest_response, check_auth


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


class ValidationError(Exception):
    pass


class Field:
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
            raise ValidationError('{} is a required field'.format(self.public_name))
        self.validate(value)
        setattr(instance, self.private_name, value)

    @abc.abstractmethod
    def validate(self, value):
        pass


class CharField(Field):
    def validate(self, value):
        if not isinstance(value, str) and value is not None:
            raise ValidationError('{} must be a string'.format(self.public_name))


class ArgumentsField(Field):
    def validate(self, value):
        if not isinstance(value, dict):
            raise ValidationError('{} must be a dictionary'.format(self.public_name))


class EmailField(Field):
    def validate(self, value):
        email_ = r'\w+@[a-z]+\.[a-z]+'
        email_templ = re.compile(email_)
        if value is not None:
            if not isinstance(value, str):
                raise ValidationError('{} must be a string'.format(self.public_name))
            elif not email_templ.fullmatch(value):
                raise ValidationError('{} is not an email address'.format(self.public_name))


class PhoneField(Field):
    def validate(self, value):
        phone_ = r'7\d{10}'
        phone_templ = re.compile(phone_)
        if value is not None:
            if not isinstance(value, (str, int)):
                raise ValidationError('{} must be a string or an integer'.format(self.public_name))
            elif ((isinstance(value, str) and not phone_templ.fullmatch(value)) or
                  (isinstance(value, int) and value//7e+10 < 1.)):
                raise ValidationError('{} is not a phone number, should start with 7'.format(self.public_name))


class DateField(Field):
    def validate(self, value):
        if value is not None:
            try:
                datetime.datetime.strptime(value, '%d.%m.%Y')
            except ValueError:
                raise ValidationError('{} must be a correct data, in format DD.MM.YYYY'.format(self.public_name))


class BirthDayField(DateField):
    def validate(self, value):
        super(BirthDayField, self).validate(value)
        if value is not None:
            now = datetime.datetime.today()
            data_tmp = datetime.datetime.strptime(value, '%d.%m.%Y')
            if now.year - data_tmp.year > 70:
                raise ValidationError('{} is older than 70 yeahs'.format(self.public_name))


class GenderField(Field):
    def validate(self, value):
        if value is not None:
            if not isinstance(value, int):
                raise ValidationError('{} must be an integer'.format(self.public_name))
            elif value not in [0, 1, 2]:
                raise ValidationError('{} must be one of [0, 1, 2]'.format(self.public_name))


class ClientIDsField(Field):
    def validate(self, value):
        if not isinstance(value, list):
            raise ValidationError('{} must be a list'.format(self.public_name))
        if len(value) == 0:
            raise ValidationError('{} must be non empty list'.format(self.public_name))
        elif sum([isinstance(i, (int, float)) for i in value]) != len(value):
            raise ValidationError('{} must be a list of numbers'.format(self.public_name))


class MetaRequest(type):
    def __new__(cls, name, bases, atts):
        clas = super().__new__(cls, name, bases, atts)
        all_atts = []
        for key, val in atts.items():
            if not key.startswith('__') and not isinstance(val, property):
                all_atts.append(key)
        setattr(clas, '__sign__', tuple(all_atts))
        return clas


class Request(metaclass=MetaRequest):

    def __init__(cls, **kwards):
        all_arg = {k: None for k in cls.__sign__}
        all_arg.update(kwards)
        for k, v in all_arg.items():
            setattr(cls, k, v)


class ClientsInterestsRequest(Request):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    @property
    def is_valid(self):
        return True


class OnlineScoreRequest(Request):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    @property
    def is_valid(self):
        if self.phone is not None and self.email is not None:
            return True
        elif self.first_name is not None and self.last_name is not None:
            return True
        elif self.gender is not None and self.birthday is not None:
            return True
        else:
            return False


class MethodRequest(Request):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == "admin"


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
        if not local_request.is_valid:
            raise ValidationError('Arguments dictionary does not have required keys')
    except ValidationError as e:
        logging.info("Validation error: %s" % e)
        code = INVALID_REQUEST
        response = getattr(e, 'message', str(e))
    except KeyError as e:
        logging.info("Attribute method is not valid: %s" % e)
        code, response = INVALID_REQUEST, "Invalid Request"
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
    except ValidationError as e:
        logging.info("Validation had not passed: %s" % getattr(e, 'message', str(e)))
        code, response = INVALID_REQUEST, "Invalid Request"
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
