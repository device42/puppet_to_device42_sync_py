# puppetexplore
Script to sync Puppet nodes information to Device42 (http://device42.com)
This script was tested with Puppet 3.8.1, Puppet 4.2. and Foreman 1.14.0.
You may use scripts for direct Puppet or/and Foreman discoveries.

# Requirements
Take the file `settings.yaml.example` and rename it to `settings.yaml`. Then change the settings to correct ones.

# Puppet Configure
You should get from the Puppet server (register client):

* client's name
* client's certificate
* key for the client's certificate
* Puppet server's CA certificate (not mandatory)
* environment name for the nodes processing


On the Puppet server for this client there should be allowed connect to endpoints:

* For Puppet version 3 or less: "{envname}/certificate_statuses/", "{envname}/node/"
* For Puppet 4: "/puppet-ca/v1/certificate_statuses/", "/puppet/v3/node/"

See files "auth.conf" and "/etc/puppetlabs/puppetserver/conf.d/ca.conf" (Puppet4)

See [NodeFilter.md](./NodeFilter.md) for node filtering options.

# Foreman Configure
Client there should be allowed connect to foreman API endpoints.

# Run
Puppet :
```
python puppetexplore.py [-c /path/to/settings.yaml]
```
Foreman :
```
python foremanexplore.py [-c /path/to/settings.yaml]
```
# Bugs / Feature Requests

Please attach node info from puppet/facter while sending bugs/feature requests. It can help to understand your specifics.
