
# LPSN API

> New in v1.0.0: Better error handling and new method `flex_search()`

Using the LPSN API requires registration. Registration is free but the usage of LPSN data is only permitted when in compliance with the LPSN copyright. See [the LPSN copyright notice](https://lpsn.dsmz.de/text/copyright) for details.

For questions, requests and comments regarding the LPSN API, please use the [LPSN contact form](https://lpsn.dsmz.de/contact).

Please register [here](https://api.lpsn.dsmz.de/login).

The Python package can be initialized using your login credentials:

```python
import lpsn

client = lpsn.LpsnClient('name@mail.example', 'password')

# the prepare method fetches all LPSN-IDs matching your query
# and returns the number of IDs found
count = client.search(taxon_name='Sulfolobus', correct_name='yes')
print(count, 'entries found.')

# the retrieve method lets you iterate over all results
# and returns the full entry as dict
# Entries can be further filtered using a list of keys (e.g. ['keywords'])
for entry in client.retrieve():
    print(entry)
```

## Example queries:

You can use IDs to query LPSN as described [here](http://api.lpsn.dsmz.de/example/fetch/520424;4948;17724). Note that when using the parameter `id`, all other parameters are ignored.

```python
# Search by LPSN-IDs (either semicolon separated or as list):
query = {"id": 520424}
query = {"id": "520424;4948;17724"}
query = {"id": [520424, 4948, 17724]}

# run query
client.search(**query)
```

Or you can use all the advanced search parameters that are described [here](https://api.lpsn.dsmz.de/example/advanced_search?category=species&riskgroup=1&page=0). 

_Note that dashes (`-`) are replaced by underscores when used as python parameters._

```python
# Example looking for validly published names of species in the genus Escherichia that have risk group 1:
client.search(taxon_name='Escherichia', category='species', riskgroup='1', validly_published='yes')

# The same example using a Python dictionary:
query = {
    'taxon-name': 'Escherichia', 
    'category': 'species',
    'riskgroup': '1',
    'validly-published': 'yes'
}
client.search(**query)
```

## New in v1.0: Flexible search

The [flexible search](https://api.lpsn.dsmz.de/example/advanced_search?category=species&riskgroup=1&page=0) has been implemented in v1.0.0.


```python
# Example looking for all entries with a basonym id that has been retreived by a previous fetch:
client.flex_search(search={"basonym_id":4370}, negate=False)
for entry in client.retrieve():
    print(entry)
```


## Filtering

Results from the `retrieve` Method of both clients can be further filtered. The result contains a list of matched keyword dicts:

```python
result = client.retrieve(filter=["full_name", "lpsn_taxonomic_status"])
print({k:v for x in result for k,v in x.items()})
```

The printed result will look like this:

```python
{782310: [{'full_name': 'Sulfolobus acidocaldarius'},
          {'lpsn_taxonomic_status': 'correct name'}],
 782311: [{'full_name': 'Sulfolobus brierleyi'},
          {'lpsn_taxonomic_status': 'synonym'}],
 782312: [{'full_name': 'Sulfolobus hakonensis'},
          {'lpsn_taxonomic_status': 'synonym'}],
 782313: [{'full_name': 'Sulfolobus metallicus'},
          {'lpsn_taxonomic_status': 'synonym'}],
...
```

## Known issues 

This package depends on `python-keycloak` for authorization and login handling. However, python-keycloak seems to have issues with older versions of requests and urllib3. See the related issue on [github](https://github.com/marcospereirampj/python-keycloak/issues/196). This might lead to the following error when trying to access the API:

```shell
AttributeError: 'Retry' object has no attribute 'allowed_methods'
```

You might be able to resolve this issue by updating the mentioned libraries, e.g. via pip:

```python
pip install requests>=2.25.1 urllib3>=1.26.5
```

