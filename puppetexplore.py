# -*- coding: utf-8 -*-

DESCRIPTION = """
    Script file puppetexplore

    Author: Alexey Kolyanov, 2015

"""

import os
import sys
import yaml
import logging
import json
import argparse

from puppetwrapper import PuppetWrapper
import device42

logger = logging.getLogger('log')
logger.setLevel(logging.INFO)
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(logging.Formatter('%(asctime)-15s\t%(levelname)s\t %(message)s'))
logger.addHandler(ch)
CUR_DIR = os.path.dirname(os.path.abspath(__file__))

parser = argparse.ArgumentParser(description="puppetexplore", epilog=DESCRIPTION)

parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')
parser.add_argument('-q', '--quiet', action='store_true', help='Quiet mode - outputs only errors')
parser.add_argument('-c', '--config', help='Config file', default='settings.yaml')
parser.add_argument('-f', '--nodefile', help='Get node info from JSON file instead of Puppet server')
parser.add_argument('-S', '--savenodes', help='Save nodes info from Puppet server to json file')

debugmode = False


def get_config(cfgpath):
    config = {}
    if not os.path.exists(cfgpath):
        if not os.path.exists(os.path.join(CUR_DIR, cfgpath)):
            raise ValueError("Config file %s is not found!" % cfgpath)
        cfgpath = os.path.join(CUR_DIR, cfgpath)
    with open(cfgpath, 'r') as cfgf:
        config = yaml.load(cfgf.read())
    return config


def d42_update(dev42, nodes, options, static_opt, from_version='3'):
    old_node = str(from_version or '3') <= '3'

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
        node_name = node['hostname']
        if options.get('as_node_name').upper() == 'FQDN':
            node_name = node.get('fqdn', node_name)

        # filtering by attributes
        # if options.get('node_filter'):
        #     if not node_filter(node, options['node_filter']):
        #         logger.info("Skip node %s: filter not passed" % node_name)
        #         continue  # filter not passed

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
                hddsize = hddsize >> 30  # convert to Gb ( hddsize/ 1024**3 )

            nodetype = None
            is_virtual = str(node['is_virtual']).lower() == 'true'
            virtual_subtype = None
            if is_virtual:
                is_virtual = 'yes'
                nodetype = 'virtual'
                if 'ec2_metadata' in node:
                    virtual_subtype = 'ec2'
            else:
                is_virtual = 'no'

            data = {
                'name': node_name,
                'type': nodetype,
                'is_it_virtual_host': is_virtual,
                'virtual_subtype': virtual_subtype,
                'os': node['operatingsystem'],
                'osver': node['operatingsystemrelease'],

                'memory': totalmem,
                'cpucount': node['processors']['count'],
                'cpucore': 0,
                'cpupower': 0,  # TODO
                'hddcount': hddcount,
                'hddsize': hddsize,

                'macaddress': node['macaddress'],
                'customer': customer_name,
                'service_level': static_opt.get('service_level'),
            }
            logger.debug("Updating node %s" % node_name)
            updateinfo = dev42.update_device(**data)
            deviceid = updateinfo['msg'][1]
            logger.info("Device %s updated/created (id %s)" % (node_name, deviceid))

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
                        'tag': ifsname,
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
                        updateinfo = dev42._post('ips', ipdata)
                        updated_ips.append(updateinfo['msg'][1])
                        logger.info("IP %s for device %s updated/created (id %s)" % (ifs['ip6'], node_name, deviceid))

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

    config = get_config(args.config)

    if not args.nodefile:
        puppet = PuppetWrapper(
            host=config['puppet_server']['host'],
            user=config['puppet_server']['user'],
            environment=config['puppet_server'].get('environment'),
            version=config['puppet_server'].get('version'),
            ca_file=config['puppet_server'].get('ca_file'),
            cert_file=config['puppet_server'].get('cert_file'),
            key_file=config['puppet_server'].get('key_file'),
        )
        puppetnodes = puppet.get_nodes()
        logger.debug("Got %s nodes from puppet" % len(puppetnodes))
    else:
        with open(args.nodefile, 'r') as nf:
            puppetnodes = [json.loads(nf.read())]

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
    d42_update(dev42, puppetnodes, config['options'], config.get('static', {}),
               from_version=config['puppet_server'].get('version'))

    return 0


if __name__ == "__main__":
    retval = main()
    sys.exit(retval)
