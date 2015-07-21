# -*- coding: utf-8 -*-

"""
    Starting from V4 the API endpoints were changed again.
    V4:
    https://docs.puppetlabs.com/puppet/4.2/reference/http_api/http_api_index.html

    Prior to V4:
    http://docs.puppetlabs.com/references/3.8.latest/developer/file.http_api_index.html

"""

import json
import requests
requests.packages.urllib3.disable_warnings()


class PuppetBaseException(Exception):
    pass


class PuppetHTTPError(PuppetBaseException):
    pass


class PuppetWrapper(object):
    """ This class might be used to call Puppet server API
        It can operate with different versions of puppet
    """

    def __init__(self, host, environment, user, version=None,
                 cert_file=None, key_file=None, ca_file=None, logger=None, onlynodes=None, **kwargs):
        self.host = host
        self.port = kwargs.get('port', '8140')
        self.environment = environment
        self.user = user
        self.ca_file = ca_file
        self.key_file = key_file
        self.cert_file = cert_file
        self.version = str(version or "3")
        self.base_url = "https://%s:%s" % (self.host, self.port)
        self.logger = logger
        self.onlynodes = onlynodes or []

    def _send(self, method, path, data=None, headers=None):
        url = "%s/%s" % (self.base_url, path)
        params = None
        if method == 'GET':
            params = data
            data = None
        headers = headers or {}
        headers.update({
            'Content-Type': 'text/json',
            'Accept': 'pson',
        })
        verify = False
        # If there is no CA file - don't verify certificates
        if self.ca_file:
            verify = self.ca_file
        resp = requests.request(method, url, data=data, params=params, cert=(self.cert_file, self.key_file),
                                verify=verify, headers=headers)
        if not resp.ok:
            raise PuppetHTTPError("HTTP %s (%s) Error %s: %s\n request was %s" %
                                  (method, path, resp.status_code, resp.text, (data or params)))
        retval = resp.json()
        return retval

    def _from_pson(self, data):
        """ Trying to extract pson-encoded objects """
        newdata = data
        if isinstance(data, list):
            newdata = [self._from_pson(d) for d in data]
        elif isinstance(data, dict):
            newdata = {}
            for k, v in data.items():
                newdata[k] = self._from_pson(v)
        elif isinstance(data, basestring):
            # try convert ruby-styled serialized Hash to python dict
            if '"=>' in data:
                try:
                    newdata = json.loads(data.replace('"=>', '": '))
                except ValueError:
                    pass
        return newdata

    def get_status(self):
        """ Auto-detect puppet version """
        spathes = [
            "puppet/v3/status/no_key?environment=%s" % self.environment,
            "%s/status/no_key" % self.environment]
        for spath in spathes:
            try:
                status = self._send('GET', spath)
                self.version = status['version']
                return status
            except:
                continue
        return None

    def get_nodes(self):
        """
            Get list of certificates and then request node info ony-by-one
        """
        self.get_status()
        old_api = self.version[0] <= '3'
        if old_api:
            certs_path = "%s/certificate_statuses/*" % (self.environment)
            nodeinfo_path_tpl = "{env}/node/{node}"
        else:
            certs_path = "puppet-ca/v1/certificate_statuses/no_key?environment=%s" % (self.environment)
            nodeinfo_path_tpl = "puppet/v3/node/{node}?environment={env}"

        csts = self._send('GET', certs_path)
        nodes_names = []
        for cst in csts:
            nodes_names.append(cst['name'])

        all_nodes = []
        for nname in nodes_names:
            path = nodeinfo_path_tpl.format(node=nname, env=self.environment)
            nodeinfo = self._send('GET', path)
            if old_api:
                nodeinfo = self._from_pson(nodeinfo['data'])
            if 'parameters' in nodeinfo:
                node = nodeinfo['parameters']
                if onlynodes:
                    if not (node.get('hostname') in onlynodes or
                            node.get('ipaddress') in onlynodes or
                            node.get('fqdn') in onlynodes or
                            node.get('uuid') in onlynodes):
                        continue
                all_nodes.append(node)

        return all_nodes
