# puppetexplore

Script to sync Puppet nodes information to Device42 (http://device42.com)

This script was tested with Puppet 3.8.1 and Puppet 4.2.


# Requirements


# Configure

Take the file `settings.yaml.example` and rename it to `settings.yaml`. Then change the settings to correct ones.

You should get from the Puppet server (register client):

* client's name
* client's certificate
* key for the client's certificate

On the Puppet server there should be allowed for this client to connect to endpoints:

* For Puppet version 3 or less: "{envname}/certificate_statuses/", "{envname}/node/"
* For Puppet 4: "/puppet-ca/v1/certificate_statuses/", "/puppet/v3/node/"

See files "auth.conf" and "/etc/puppetlabs/puppetserver/conf.d/ca.conf" (Puppet4)


# Run

```
    python puppetexplore.py [-c /path/to/settings.yaml]
```

# Bugs / Feature Requests

Please attach node info from puppet/facter while sending bugs/feature requests. It can help to understand your specifics.
