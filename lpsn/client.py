'''
Using the LPSN API requires registration. Registrations is free but the usage 
of LPSN data is only permitted when in compliance with the LPSN copyright. 
See https://lpsn.dsmz.de/text/copyright for details.

Please register at https://api.lpsn.dsmz.de/login.
'''

from keycloak.exceptions import KeycloakAuthenticationError
from keycloak import KeycloakOpenID
import requests
import json


class LpsnClient():
    def __init__(self, user, password, public=True):
        ''' Initialize client and authenticate on the server '''
        self.result = {}
        self.public = public

        client_id = "api.lpsn.public"
        if self.public:
            server_url = "https://sso.dsmz.de/auth/"
        else:
            server_url = "https://sso.dmz.dsmz.de/auth/"
        try:
            self.keycloak_openid = KeycloakOpenID(
                server_url=server_url,
                client_id=client_id,
                realm_name="dsmz")

            # Get tokens
            token = self.keycloak_openid.token(user, password)
            self.access_token = token['access_token']
            self.refresh_token = token['refresh_token']
            print("-- Authentification successful --")
        except KeycloakAuthenticationError as e:
            print("ERROR - Authentification failed:", e)

    def do_api_call(self, url):
        ''' Initialize API call on given URL and returns result as json '''
        if self.public:
            baseurl = "https://api.lpsn.dsmz.de/"
        else:
            baseurl = "http://api.pnu-dev.dsmz.local/"
        
        if not url.startswith("http"):
            # if base is missing add default:
            url = baseurl + url
        resp = self.do_request(url)
        if resp.status_code == 500 or resp.status_code == 400:
            return json.loads(resp.content)
        elif (resp.status_code == 401):
            msg = json.loads(resp.content)

            if msg['message'] == "Expired token":
                # Access token might have expired (15 minutes life time).
                # Get new tokens using refresh token and try again.
                token = self.keycloak_openid.refresh_token(self.refresh_token)
                self.access_token = token['access_token']
                self.refresh_token = token['refresh_token']
                return self.do_api_call(url)
                
            return msg
        else:
            return json.loads(resp.content)

    def do_request(self, url):
        ''' Perform request with authentification '''
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer {token}".format(token=self.access_token)
        }

        resp = requests.get(url, headers=headers)
        return resp

    def filterResult(self, d, keys):
        ''' Helper function to filter nested dict by keys '''
        if not isinstance(d, dict):
            yield None
        for k, v in d.items():
            if k in keys:
                yield {k: v}
            if isinstance(v, dict):
                yield from self.filterResult(v, keys)
            elif isinstance(v, list):
                for i in v:
                    if isinstance(i, dict):
                        yield from self.filterResult(i, keys)

    def retrieve(self, filter=None):
        ''' Yields all the received entries and does next call if result is incomplete '''
        ids = ";".join([str(i) for i in self.result['results']])
        entries = self.do_api_call('fetch/'+ids)['results']
        for el in entries:
            if isinstance(el, dict):
                entry = el
                el = entry.get("id")
            else:
                entry = entries[el]
            if filter:
                entry = {el: [i for i in self.filterResult(entry, filter)]}
            yield entry
        if self.result['next']:
            self.result = self.do_api_call(self.result['next'])
            yield from self.retrieve(filter)

    def search(self, **params):
        ''' Initialize search with parameters
        '''
        if 'id' in params:
            query = params['id']
            if type(query) == type(""):
                query = query.split(';')
            self.result = {'count': len(query), 'next': None,
                           'previous': None, 'results': query}
            return self.result['count']

        query = []
        for k, v in params.items():
            k = k.replace("_", "-")
            if v == True:
                v = "yes"
            elif v == False:
                v = "no"
            else:
                v = str(v)
            query.append(k + "=" + v)
        self.result = self.do_api_call('advanced_search?'+'&'.join(query))

        if not self.result:
            print("ERROR: Something went wrong. Please check your query and try again")
            return 0
            
        if not 'count' in self.result:
            print("ERROR:", self.result.get("title"))
            print(self.result.get("message"))
            return 0
            
        if self.result['count'] == 0:
            print("Your search did not receive any results.")
            return 0
            
        return self.result['count']


if __name__ == "__main__":
    client = LpsnClient('name@mail.example', 'password')

    # the prepare method fetches all LPSN-IDs matching your query
    # and returns the number of IDs found
    count = client.search(category='species', taxon_name='Sulfolobus')
    print(count, 'entries found.')

    # The retrieve method lets you iterate over all entries
    # and returns the full entry as dict
    # Entries can be further filtered using a list of keys (e.g. ['full_name', 'lpsn_taxonomic_status'])
    for entry in client.retrieve():
        print(entry)
