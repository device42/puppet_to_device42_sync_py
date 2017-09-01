# -*- coding: utf-8 -*-

import os
import sys
import yaml
import logging
import json
import re
import argparse

from puppetwrapper import PuppetWrapper
import device42
from nodefilter import node_filter


logger = logging.getLogger('log')
logger.setLevel(logging.INFO)
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(logging.Formatter('%(asctime)-15s\t%(levelname)s\t %(message)s'))
logger.addHandler(ch)
CUR_DIR = os.path.dirname(os.path.abspath(__file__))

parser = argparse.ArgumentParser(description="puppetexplore")

parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')
parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode - outputs only errors')
parser.add_argument('-c', '--config', help='Config file', default='settings.yaml')
parser.add_argument('-f', '--nodefile', help='Get node info from JSON file instead of Puppet server')
parser.add_argument('-S', '--savenodes', help='Save nodes info from Puppet server to json file')
parser.add_argument('-n', '--onlynode', action='append', help='Process only selected nodes (fqdn or hostname)')

debugmode = False
cpuf_re = re.compile(r'@ ([\w\d\.]+)GHz', re.I)


def get_config(cfgpath):
    if not os.path.exists(cfgpath):
        if not os.path.exists(os.path.join(CUR_DIR, cfgpath)):
            raise ValueError("Config file %s is not found!" % cfgpath)
        cfgpath = os.path.join(CUR_DIR, cfgpath)
    with open(cfgpath, 'r') as cfgf:
        config = yaml.load(cfgf.read())
    return config


def d42_update(dev42, nodes, options, static_opt, mapping, from_version='3', puppethost=None):
    old_node = str(from_version or '3')[0] <= '3'

    # get customer info
    customer_name = static_opt.get('customer')
    customer_id = str(static_opt.get('customer_id') or '') or None
    if (not customer_id and customer_name) or (customer_id and not customer_name):
        allcustomers = dev42._get('customers')['Customers']
        for cst in allcustomers:
            if customer_id and str(cst['id']) == customer_id:
                customer_name = cst['name']
                break
            if customer_name and cst['name'] == customer_name:
                customer_id = str(cst['id'])
                break
    logger.debug("Customer %s: '%s'" % (customer_id, customer_name))

    # processing all nodes
    for node in nodes:

        if 'hostname' not in node:
            logger.debug("Skip node: no name found")
            continue

        if options.get('show_node'):
            print node

        node_name = node['hostname']
        if options.get('as_node_name').upper() == 'FQDN':
            node_name = node.get('fqdn', node_name)

        # filtering by attributes
        if options.get('node_filter'):
            if not node_filter(node, options['node_filter']):
                logger.info("Skip node %s: filter not passed" % node_name)
                continue  # filter not passed

        try:
            # device = dev42.get_device_by_name(node_name)

            # detect memory
            totalmem = int(float(node['memorysize_mb']))

            # detect HDD
            hddcount = 0
            hddsize = 0  # first in bytes, then should be converted to Gb
            if 'disks' in node:
                for p in node['disks'].values():
                    hddcount += 1
                    hddsize += int(p.get('size_bytes') or 0)
                if hddsize > 0:
                    hddsize = 1.0 * hddsize / 1000 ** 3  # convert to Gb ( hddsize/ 1024**3 )

            nodetype = None
            is_virtual = str(node['is_virtual']).lower() == 'true'
            virtual_subtype = None
            if is_virtual:
                is_virtual = 'yes'
                nodetype = 'virtual'
                virtual_subtype = 'other'
                if 'ec2_metadata' in node:
                    virtual_subtype = 'ec2'
            else:
                is_virtual = 'no'

            cpupower = 0
            cpucount = node['physicalprocessorcount']
            cpucores = node['processorcount']
            
            try:
   	        cpupowers = cpuf_re.findall(node['processors']['models'][0])
            except TypeError:
                cpupowers = None            

            if cpupowers:
                cpupower = int(float(cpupowers[0]) * 1000)

            data = {
                'name': node_name,
                'type': nodetype,
                'is_it_virtual_host': is_virtual,
                'virtual_subtype': virtual_subtype,
                'os': node['operatingsystem'],
                'osver': node['operatingsystemrelease'],

                'memory': totalmem,
                'cpucount': cpucount,
                'cpucore': cpucores,
                'cpupower': cpupower,
                'hddcount': hddcount,
                'hddsize': hddsize,

                'macaddress': node['macaddress'],
                'customer': customer_name,
                'service_level': static_opt.get('service_level'),
            }

            if options.get('hostname_precedence'):
                data.update({'new_name': node_name})

            if options.get('tags'):
                data.update({'tags': options.get('tags')})

            logger.debug("Updating node %s" % node_name)
            updateinfo = dev42.update_device(**data)
            deviceid = updateinfo['msg'][1]
            logger.info("Device %s updated/created (id %s)" % (node_name, deviceid))

            if puppethost:
                cfdata = {
                    'name': node_name,
                    'key': 'Puppet Node ID',
                    'value': node_name,
                    'notes': 'Puppet Server %s' % puppethost
                }
                updateinfo = dev42._put('device/custom_field', cfdata)

            global depth
            depth = []
            res = []
            def get_depth(obj):
                global depth
                for item in obj:
                    depth.append(item)
                    if type(obj[item]) == str:
                      res.append({obj[item]: depth})
                      depth = []
                    else:
                      get_depth(obj[item])
                return res

            if mapping:
                full_depth = get_depth(mapping)
                for element in full_depth:
                    for key in element:
                        value = None
                        step = node

                        try:
                            for x in element[key]:
                                step = step[x]
                        except KeyError:
                            continue

                        if type(step) in [unicode, str, int]:
                            value = step
                        elif type(step) in [list, tuple, dict]:
                            value = len(step)

                        cfdata = {
                            'name': node_name,
                            'key': key,
                            'value': value
                        }
                        updateinfo = dev42._put('device/custom_field', cfdata)

            # Dealing with IPs
            device_ips = dev42._get("ips", data={'device': node_name})['ips']
            updated_ips = []

            if old_node:
                # Puppet with version <= 3 has plain structure and does not know about IPv6
                for ifsname in node['interfaces'].split(','):
                    if ifsname == 'lo':
                        continue  # filter out local interface
                    ipaddr = node['ipaddress_%s' % ifsname.lower()]
                    if ipaddr.startswith('127.0'):
                        continue  # local loopbacks
                    macaddr = node['macaddress_%s' % ifsname.lower()]
                    # update IPv4
                    ipdata = {
                        'ipaddress': ipaddr,
                        'tag': ifsname.replace('_', ' '),
                        'device': node_name,
                        'macaddress': macaddr,
                    }
                    # logger.debug("IP data: %s" % ipdata)
                    updateinfo = dev42._post('ips', ipdata)
                    updated_ips.append(updateinfo['msg'][1])
                    logger.info("IP %s for device %s updated/created (id %s)" % (ipaddr, node_name, deviceid))

            elif node.get('networking'):
                # Puppet v4 is more detailed
                for ifsname, ifs in node['networking']['interfaces'].items():
                    if ifsname == 'lo':
                        continue  # filter out local interface
                    if ifs['ip'].startswith('127.0'):
                        continue  # local loopbacks
                    # update IPv4
                    ipdata = {
                        'ipaddress': ifs['ip'],
                        'tag': ifsname,
                        'device': node_name,
                        'macaddress': ifs['mac'],
                    }
                    # logger.debug("IP data: %s" % ipdata)
                    updateinfo = dev42._post('ips', ipdata)
                    updated_ips.append(updateinfo['msg'][1])
                    logger.info("IP %s for device %s updated/created (id %s)" % (ifs['ip'], node_name, deviceid))
                    # update IPv6
                    if 'ip6' in ifs and len(ifs['ip6']) > 6:
                        ipdata = {
                            'ipaddress': ifs['ip6'],
                            'tag': ifsname,
                            'device': node_name,
                            'macaddress': ifs['mac'],
                        }
                        # logger.debug("IP data: %s" % ipdata)
                        try:
                            updateinfo = dev42._post('ips', ipdata)
                            updated_ips.append(updateinfo['msg'][1])
                            logger.info("IP %s for device %s updated/created (id %s)" % (ifs['ip6'], node_name, deviceid))
                        except device42.Device42HTTPError as e:
                            print e

            # Delete other IPs from the device
            if updated_ips:
                for d_ip in device_ips:
                    if d_ip['id'] not in updated_ips:
                        dev42._delete('ips/%s' % d_ip['id'])
                        logger.debug("Deleted IP %s (id %s) for device %s (id %s)" %
                                     (d_ip['ip'], d_ip['id'], node_name, deviceid))
        except Exception as eee:
            logger.exception("Error(%s) updating device %s" % (type(eee), node_name))


class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, datetime):
            return o.strftime("%Y %m %d %H:%M:%S")
        return json.JSONEncoder.default(self, o)


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

    pupversion = None
    if not args.nodefile:
        puppet = PuppetWrapper(
            host=config['puppet_server']['host'],
            user=config['puppet_server']['user'],
            environment=config['puppet_server'].get('environment'),
            version=config['puppet_server'].get('version'),
            ca_file=config['puppet_server'].get('ca_file'),
            cert_file=config['puppet_server'].get('cert_file'),
            key_file=config['puppet_server'].get('key_file'),
            logger=logger,
            onlynodes=onlynodes,
        )
        puppetnodes = puppet.get_nodes()
        logger.debug("Got %s nodes from puppet (v%s)" % (len(puppetnodes), puppet.version))
        pupversion = puppet.version
    else:
        with open(args.nodefile, 'r') as nf:
            allpuppetnodes = json.loads(nf.read())
        if isinstance(allpuppetnodes, dict):
            allpuppetnodes = [allpuppetnodes]
        pupversion = 0
        puppetnodes = allpuppetnodes
        if onlynodes:
            puppetnodes = []
            for node in allpuppetnodes:
                if not (node.get('hostname') in onlynodes or
                        node.get('ipaddress') in onlynodes or
                        node.get('fqdn') in onlynodes or
                        node.get('uuid') in onlynodes):
                    continue
                puppetnodes.append(node)
        if puppetnodes:
            pupversion = puppetnodes[0]['clientversion']
        logger.debug("Got %s nodes from file (v%s)" % (len(puppetnodes), pupversion))

    if args.savenodes:
        with open(args.savenodes, 'w') as wnf:
            wnf.write(json.dumps(puppetnodes, cls=JSONEncoder, indent=4, sort_keys=True, ensure_ascii=False))

    dev42 = device42.Device42(
        endpoint=config['device42']['host'],
        user=config['device42']['user'],
        password=config['device42']['pass'],
        logger=logger,
        debug=debugmode
    )
    d42_update(dev42, puppetnodes, config['options'], config.get('static', {}), config.get('mapping', {}),
               from_version=pupversion, puppethost=config['puppet_server']['host'])

    return 0


if __name__ == "__main__":
    retval = main()
    print 'Done'
    sys.exit(retval)
