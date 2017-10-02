# puppetexplore
Script to sync Puppet nodes information to Device42 (http://device42.com)
This script was tested with Puppet 3.8.1, Puppet 4.2. and Foreman 1.14.0.
You may use scripts for direct Puppet or/and Foreman discoveries.

# Requirements
Take the file `settings.yaml.example` and rename it to `settings.yaml`. Then change the settings to correct ones.
Install `requirements.txt` with pip. Please note that you need installed `python-devel`.

# Puppet Configure
For proper connection clients certificate should be signed on puppet server and you should provide:

* server username
* client's certificate ( $HOME/.puppetlabs/etc/puppet/ssl/cert/<<node_name>>.pem, /etc/puppetlabs/puppet/ssl/cert/<<node_name>>.pem )
* key for the client's certificate ( $HOME/.puppetlabs/etc/puppet/ssl/private_key/<<node_name>>.pem, /etc/puppetlabs/puppet/ssl/private_key/<<node_name>>.pem )
* CA certificate (not mandatory) ( $HOME/.puppetlabs/etc/puppet/ssl/certs/ca.pem, /etc/puppetlabs/puppet/ssl/certs/ca.pem )
* environment name for the nodes processing


On the Puppet server for this client there should be allowed connect to endpoints:

* For Puppet version 3 or less: "{envname}/certificate_statuses/", "{envname}/node/"
* For Puppet 4: "/puppet-ca/v1/certificate_statuses/[*]", "/puppet/v3/node/"

See files "auth.conf" and "/etc/puppetlabs/puppetserver/conf.d/ca.conf" (Puppet4).
Please check config for default "/puppet-ca/v1/certificate_statuses/" restrictions, if found - edit or remove.

See [NodeFilter.md](./NodeFilter.md) for node filtering options.

# Foreman Configure
Client should be allowed to connect to foreman api.

# Custom Fields Mapping
You may send any variable from nodes. Just define `mapping` section in `settings.yaml` ( we have commented example ). 

If variable are tuple, list or dict we send length of the particular object. 

If you want to see all possible node values, please use `show_node` parameter in `settings.yaml` `options` section.

# Run
Puppet :
```
python puppetexplore.py [-c /path/to/settings.yaml]
```
Foreman :
```
python foremanexplore.py [-c /path/to/settings.yaml]
```

# Command List
```
  -h, --help            show help message and exit
  -d, --debug           Enable debug output
  -q, --quiet           Quiet mode - outputs only errors
  -c CONFIG, --config CONFIG
                        Config file
  -f NODEFILE, --nodefile NODEFILE
                        Get node info from JSON file instead of Puppet server
  -S SAVENODES, --savenodes SAVENODES
                        Save nodes info from Puppet server to json file
  -n ONLYNODE, --onlynode ONLYNODE
                        Process only selected nodes (fqdn or hostname)
```

# Bugs / Feature Requests

Please attach node info from puppet/facter while sending bugs/feature requests. It can help to understand your specifics.
