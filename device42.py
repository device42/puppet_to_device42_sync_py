# -*- coding: utf-8 -*-

"""
    Lightweight wrapper for Device42 API: http://api.device42.com

    Author: Alexey Kolyanov, 2015
"""

import os
import requests
requests.packages.urllib3.disable_warnings()


class Device42BaseException(Exception):
    pass


class Device42BadArgumentError(Exception):
    pass


class Device42HTTPError(Device42BaseException):
    pass


class Device42WrongRequest(Device42HTTPError):
    pass


class Device42(object):

    def __init__(self, endpoint, user, password, **kwargs):
        self.base = endpoint
        self.user = user
        self.pwd = password
        self.verify_cert = False
        self.debug = kwargs.get('debug', False)
        self.logger = kwargs.get('logger', None)
        self.base_url = "https://%s/api/1.0" % self.base
        self.headers = {}

    def _send(self, method, path, data=None):
        """ General method to send requests """
        url = "%s/%s" % (self.base_url, path)
        params = None
        if method == 'GET':
            params = data
            data = None
        resp = requests.request(method, url, data=data, params=params,
                                auth=(self.user, self.pwd),
                                verify=self.verify_cert, headers=self.headers)
        if not resp.ok:
            raise Device42HTTPError("HTTP %s (%s) Error %s: %s\n request was %s" %
                                    (method, path, resp.status_code, resp.text, data))
        retval = resp.json()
        # print(retval)
        return retval

    def _get(self, path, data=None):
        return self._send("GET", path, data=data)

    def _post(self, path, data):
        if not path.endswith('/'):
            path += '/'
        return self._send("POST", path, data=data)

    def _put(self, path, data):
        if not path.endswith('/'):
            path += '/'
        return self._send("PUT", path, data=data)

    def _delete(self, path):
        return self._send("DELETE", path)

    def _log(self, message, level="DEBUG"):
        if self.logger:
            self.logger.log(level.upper(), message)

    def update_device(self, **kwargs):
        """ See http://api.device42.com/#create/update-device-by-name """
        path = 'devices'
        atleast_fields = "name serial_no uuid".split()
        known_fields = "new_name asset_no manufacturer hardware new_hardware is_it_switch"
        known_fields += " is_it_virtual_host is_it_blade_host in_service type service_level virtual_host"
        known_fields += " blade_host slot_no storage_room_id storage_room os osver memory cpucount cpupower cpucore"
        known_fields += " hddcount hddsize hddraid hddraid_type macaddress devices_in_cluster appcomps"
        known_fields += " customer contract_id contract"
        known_fields += " aliases subtype virtual_subtype notes tags"
        known_fields = atleast_fields + known_fields.split()
        if not set(atleast_fields).intersection(kwargs.keys()):
            raise Device42BadArgumentError("At least one parameter should be passed: %s" % atleast_fields)
        unknown_fields = set(kwargs.keys()) - set(known_fields)
        if unknown_fields:
            raise Device42BadArgumentError("Unknown parameters: %s" % unknown_fields)
        return self._post(path, data=kwargs)

    def get_device_by_name(self, name):
        path = "devices/name/%s" % name
        return self._get(path)
