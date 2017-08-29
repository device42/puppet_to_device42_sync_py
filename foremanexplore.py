# -*- coding: utf-8 -*-

import os
import sys
import logging
import json
import re
import ast
import argparse
import device42
import requests

from foreman.client import Foreman
from puppetexplore import JSONEncoder, get_config, d42_update
requests.packages.urllib3.disable_warnings()
logging.getLogger('foreman.client').setLevel(logging.CRITICAL)

logger = logging.getLogger('log')
CUR_DIR = os.path.dirname(os.path.abspath(__file__))

parser = argparse.ArgumentParser(description="foremanexploer")

parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')
parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode - outputs only errors')
parser.add_argument('-c', '--config', help='Config file', default='settings.yaml')
parser.add_argument('-S', '--savenodes', help='Save nodes info from Puppet server to json file')
parser.add_argument('-n', '--onlynode', action='append', help='Process only selected nodes (fqdn or hostname)')

debugmode = False
cpuf_re = re.compile(r'@ ([\w\d\.]+)GHz', re.I)


def main():
    global debugmode
    args = parser.parse_args()
    if args.debug:
        logger.setLevel(logging.DEBUG)
        debugmode = True
    if args.quiet:
        logger.setLevel(logging.ERROR)
        debugmode = False
    onlynodes = []
    if args.onlynode:
        onlynodes = args.onlynode

    config = get_config(args.config)
    host = config['foreman']['host']
    user = config['foreman']['user']
    password = config['foreman']['pass']

    f = Foreman('https://%s' % host, (user, password), verify=False)
    node_ids = []
    for node in f.hosts.index(per_page=100000):
        node = node['host']
        if len(onlynodes) > 0 and node['name'] in onlynodes:
            node_ids.append(node['id'])
        elif len(onlynodes) == 0:
            node_ids.append(node['id'])

    facts_query = 'fqdn or memorysize_mb or is_virtual or processorcount or processors::models or serialnumber' 

    nodes = []
    for node_id in node_ids:

        host = f.hosts.show(id=node_id)['host']

        if len(onlynodes) > 0 and host['name'] not in onlynodes:
            continue

        host['model'] = f.models.show(id=host['model_id'])
        host['os'] = f.operatingsystems.show(id=host['operatingsystem_id'])
        facts = f.do_get('/api/hosts/%s/facts?search=%s&per_page=999' % (node_id, facts_query), {})
        facts = facts[host['name']] if host['name'] in facts else {}
        disks = f.do_get('/api/hosts/%s/facts?search=disks&per_page=999' % node_id, {})
        disks = disks[host['name']] if host['name'] in disks else {}
        ec2_metadata = f.do_get('/api/hosts/%s/facts?search=ec2_metadata&per_page=999' % node_id, {})
        ec2_metadata = ec2_metadata[host['name']] if host['name'] in ec2_metadata else {}
        networking = f.do_get('/api/hosts/%s/facts?search=networking&per_page=999' % node_id, {})
        networking = networking[host['name']] if host['name'] in networking else {}

        if facts == {}:
		continue

        formatted_disks = {}
        for key in disks:
            splitted = key.split('::')
            if len(splitted) == 3:
                if splitted[2] == 'size_bytes':
                    formatted_disks[splitted[1]] = {
                        'size_bytes': disks[key]
                    }

        formatted_interfaces = {}
        for key in networking:
            splitted = key.split('::')
            if len(splitted) == 4:
                if splitted[2] not in formatted_interfaces:
                    formatted_interfaces[splitted[2]] = {}
                formatted_interfaces[splitted[2]].update({splitted[3]: networking[key]})

	# Check to see that we have all data, or set it to '' if not
	if facts.has_key('is_virtual'):
		_is_virtual = facts['is_virtual'] 
	else:
		_is_virtual = False
        if facts.has_key('serialnumber'):
		_serialnumber = facts['serialnumber']
	else:
		_serialnumber = ''
        if facts.has_key('processors::models'):
		_processors_models = ast.literal_eval(facts['processors::models'])
	else:
		_processors_models = ['']
        # prepare correct format
        data = {
            'hostname': host['name'],
            'memorysize_mb': facts['memorysize_mb'],
            'fqdn': facts['fqdn'],
            'disks': formatted_disks,
            'is_virtual': _is_virtual,
            'serial_no': _serialnumber,
            'physicalprocessorcount': facts['physicalprocessorcount'],
            'processorcount': facts['processorcount'],
            'processors': {
                'models': _processors_models
            },
            'operatingsystem': host['os']['operatingsystem']['name'],
            'operatingsystemrelease': host['os']['operatingsystem']['release_name'],
            'macaddress': host['mac'],
            'networking': {
                'interfaces': formatted_interfaces
            }
        }
        if len(ec2_metadata) > 0:
            data.update({'ec2_metadata': ec2_metadata})

        nodes.append(data)

    if args.savenodes:
        with open(args.savenodes, 'w') as wnf:
            wnf.write(json.dumps(nodes, cls=JSONEncoder, indent=4, sort_keys=True, ensure_ascii=False))

    dev42 = device42.Device42(
        endpoint=config['device42']['host'],
        user=config['device42']['user'],
        password=config['device42']['pass'],
        logger=logger,
        debug=debugmode
    )

    d42_update(dev42, nodes, config['options'], config.get('static', {}),
               from_version='4', puppethost=config['foreman']['host'])

    return 0

if __name__ == "__main__":
    retval = main()
    print 'Done'
    sys.exit(retval)
