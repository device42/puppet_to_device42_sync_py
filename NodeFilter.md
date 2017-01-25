# Filter nodes by attribute values

There might be useful to process only specific nodes, having some values in the attributes. You may use `node_filter` in the settings (`options`) for this purpose.

Node filter might contain a list of filters applied to the attributes received from the Puppet (Facter). If **all** filters are successed - the node will be processed, otherwise skipped.

Example:
```
options:
    as_node_name: fqdn
    node_filter:
        # node platform should be equal to 'ubuntu', case-insensitive
        -
            attribute: platform
            value: ubuntu
            compare: iequal
            invert: false
        # node 'kernel.release' attribute should be equal or greater than '3.13', case-insensitive string comparing
        -
            attribute: kernel.release
            value: "3.13"
            compare: igt
```


## Attribute Path

If the attribute placed inside the tree, you may specify the path by keys separated with dots: `attribute: kernel.release`


## Inversion

If required to invert the result of operation, set the parameter `invert: true` for the filter.

Example: match all non-ubuntu nodes
```
        node_filter:
        -
            attribute: platform
            value: ubuntu
            compare: iequal
            invert: true
```


## Supported operations by attribute types

### String

For any string operator there can be 2 forms: case-insensitive and case-sensitive.

Below described only case-insensitive operators, to get strict comparing remove the 'i' prefix.


#### iequal, ieq

String equality

Example: Node platform should be equal to 'ubuntu', case-insensitive
```
        node_filter:
        -
            attribute: platform
            value: ubuntu
            compare: iequal
            invert: false
```


#### igreater, igt

String in attribute should be great **or equal** to 'value' .


#### iless, ilt

String in attribute should be less **or equal** to 'value' .


#### isubstr, icontains

attribute contains substring from 'value'.


#### iin

Attribute is contained in 'value' (as list)

Example:
```
        node_filter:
        -
            attribute: platform
            value: [ubuntu, centos, fedora]
            compare: iin
```


### Int, Float

#### equal, eq

Attribute equals to 'value'


#### greater, gt

Atribute greater **or equal** than 'value'


#### less, lt

Atribute less **or equal** than 'value'


### Bool

Parameter 'compare' is ignored, Attribute and 'value' are compared against each other.


### List, Dictionary

For dictionary the comparison operations are performed over its keys only.

#### empty

The attribute should be empty

#### has, contains (ihas, icontains)

Attribute contains the 'value' (both case-(in)sensitive forms)
