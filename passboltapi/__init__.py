import configparser
from http.cookiejar import LWPCookieJar
import json
import logging
import urllib.parse
from typing import List, Mapping, Optional, Tuple, Union

import uuid
import datetime
import jwt
import cryptography

import gnupg
import requests
from urllib3.exceptions import HeaderParsingError

from passboltapi.schema import (
    AllPassboltTupleTypes,
    PassboltDateTimeType,
    PassboltFavoriteDetailsType,
    PassboltFolderIdType,
    PassboltFolderTuple,
    PassboltGroupIdType,
    PassboltGroupTuple,
    PassboltOpenPgpKeyIdType,
    PassboltOpenPgpKeyTuple,
    PassboltPermissionIdType,
    PassboltPermissionTuple,
    PassboltResourceIdType,
    PassboltResourceTuple,
    PassboltResourceType,
    PassboltResourceTypeIdType,
    PassboltResourceTypeTuple,
    PassboltRoleIdType,
    PassboltSecretIdType,
    PassboltSecretTuple,
    PassboltUserIdType,
    PassboltUserTuple,
    tuple_constructor,
)

JWT = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovLzEwLjIyMS4yMjEuMTA1OjI3NDQzLyIsInN1YiI6ImZlMGJhN2Q0LWRlYTctNDNhYy1hYzE1LWMzZDM1ZGEzMjMxYSIsImV4cCI6MTc0MDQzMjUwOH0.PkA5yvQD8gDx3R-fNWQgRDG2aVik70Wg1RY2GbYkPs5aXpGr8Dt2ahN1p2fi0AfIhosGWser1SHer0czvytp1qpVyql-e4pdosnxrqT7vLjRQvQfzn5keSIyNhB2upEUkYWRb6ogpd-du3aYOjSNBE1PxckDi14WGTmK1GMF5jpiPyae8dvg7CUTTrYCrszRlFknlNr2r5pOLbcWO-p-mui77oykCz2VmGHlSD2UCYsQopIjJZNmHel6LQeCzucI3rhv0QgUJ4ZKstrRS17xC9HQoiGlpLYI5s_lvMUeYUJlRn7PKcHwkDd1mplZodXmLAgHvCKzzBgUxh11D7J5Z8rEq24q9PFADwrwXydCpipSUW21JHomP4x3FgBlQ6JA9f4JqSc8RYe7ZOKPrGv4zq9um2ECs94ZUbQFZ4b3Sqs1UTmzaal14C_cSlRbzl2G1ngkuZ9YbJGZ_pw3WWi4TItATBAy6NqiM5KPaI4gZheBmt3QinBm9iC17y9A_AMBUGijpBIaDMOWfNzwvhB2zrrrJysuZI4c5hUJg8LCNV8NVmgPJflQJmHfgb3OSAjb9YhNyQErH5J_fChNfKXJeBrRJVJGwr8kHly7TWaQo8zIbi_k9pwRL2WN3MVGjpAlfjgDslhluk5LfL5oOStuGyE4xtSAoXJONRotiP7JNmc'

class PassboltSession(requests.Session):
    def __init__(self) -> None:
        super().__init__()
        self.server_jwt_public_key = None

    def _is_session_valid(self, auth_header: str):
        try:
            # print(self.server_jwt_public_key)
            #todo: add signature verification of the jwt
            decoded = jwt.decode(JWT, options={'verify_signature': False}, algorithms=['RS256'])
            # print(decoded)
        except Exception as e:
            raise e
        return

    def request(self, method, *args, **kwargs):
        # __import__('pprint').pprint(self.headers)
        if 'Authorization' in self.headers.keys():
            self._is_session_valid(str(self.headers['Authorization']))
        else:
            pass
            # print('no auth')
            # self._is_session_valid(self.headers['Authorization'])
        # print('AUTH') if 'Authorization' in self.headers.keys() else print('No AUTH')
        #check if the session is expired
        response = super().request(method, *args, **kwargs)
        return response


class PassboltAPI():
    def __init__(
        self,
        config: Optional[str] = None,
        config_path: Optional[str]|None = None,
    ):
        self.gpg = gnupg.GPG()
        self.user_fingerprint = ''
        self.server_url = ''
        self.server_fingerprint = ''
        self.jwt_auth_token     = None
        self.jwt_refresh_token  = None
        self.server_jwt_public_key = None
        self.config = {}

        # ----------------------------------
        # check config
        # ----------------------------------
        # the dictionary config has precedence over the config_path
        # ----------------------------------
        if not config:
            if not config_path:
                raise ValueError("PassboltAPI class requires the 'config' or the 'config_path' parameter set.")

            self.config = configparser.ConfigParser()
            self.config.read_file(open(config_path))
            self.config = dict(self.config['passbolt'])
        else:
            self.config = config

        # ----------------------------------
        # read config
        # ----------------------------------
        self.server_url = self.config['server']
        self.user_fingerprint = self.config["user_fingerprint"].upper().replace(" ", "")
        self.gpg_passphrase = self.config["passphrase"]
        try:
            self.gpg_fingerprint = [i for i in self.gpg.list_keys() if i["fingerprint"] == self.user_fingerprint][0]["fingerprint"]
        except IndexError:
            raise Exception("GPG public key could not be found. Check: gpg --list-keys")

        if self.user_fingerprint not in [i["fingerprint"] for i in self.gpg.list_keys(True)]:
            raise Exception("GPG private key could not be found. Check: gpg --list-secret-keys")

        # ----------------------------------
        # http session setup
        # ----------------------------------
        self.http_session = PassboltSession()
        proxies = {
            "http":"http://127.0.0.1:8080",
            "https":"http://127.0.0.1:8080"
        }
        self.http_session.proxies.update(proxies)
        # todo: add server verification
        self.http_session.verify = False

        # ----------------------------------
        # authenticate
        # ----------------------------------
        self.import_server_public_key()
        self.authenticate()

# ///////////////////////////////////////////////////////////////////////////////////

    def _check_passbolt_response(self, response: requests.Response):
        if response.status_code != 200:
            raise requests.HTTPError(f"Unexpected status code ({response.status_code}) in response from {response.url}\nResponse: {response.content}", response=response)

        if "application/json" not in response.headers.get("Content-Type", ""):
            raise requests.HTTPError(f"Not a JSON response from {response.url}.\nResponse: {response}", response=response)

        body = response.json()
        if not {"header", "body"}.issubset(body.keys()):
            raise requests.HTTPError(f"Unexpected passbolt response: {body}", response=response)

        if body['header']['status'] != 'success':
            raise requests.HTTPError(f"Unexpected status code {response.status_code}", response=response)

# ///////////////////////////////////////////////////////////////////////////////////

    def get_jwt_rsa_server_info(self):
        r = self.http_session.get(f"{self.server_url}/auth/jwt/rsa.json")
        self._check_passbolt_response(r)
        self.server_jwt_public_key = r.json()['body']['keydata']
        self.http_session.server_jwt_public_key = r.json()['body']['keydata']
        # print(self.http_session.server_jwt_public_key)

# ///////////////////////////////////////////////////////////////////////////////////

    def get_resources(self) -> List[PassboltResourceTuple]:
        params = {}
        r = self.http_session.get(f"{self.server_url}/resources.json", params=params)
        self._check_passbolt_response(r)
        resources = tuple_constructor(PassboltResourceTuple)(r.json()['body'])
        return resources

# ///////////////////////////////////////////////////////////////////////////////////

    def get_folders(
        self,
        search_filter: Optional[str] = None,
        include_children_resources: Optional[bool] = False,
    ) -> List[PassboltFolderTuple]:
        params = {}
        if search_filter:
            params['filter[search]'] = search_filter
        if include_children_resources:
            params['contain[children_resources]'] = 1

        r = self.http_session.get(f"{self.server_url}/folders.json", params=params)
        self._check_passbolt_response(r)

        folders = tuple_constructor(
            PassboltFolderTuple,
            subconstructors={
                "children_resources": tuple_constructor(PassboltResourceTuple)
            }
        )(r.json()['body'])

        return folders

# ///////////////////////////////////////////////////////////////////////////////////

    def get_users(
        self,
        is_admin: bool = False,
        is_active: bool = False,
    ):
        params = {}
        if is_admin:
            params['filter[is-admin]'] = True
        if is_active:
            params['filter[is-active]'] = True

        r = self.http_session.get(f"{self.server_url}/users.json", params=params)
        self._check_passbolt_response(r)

        users = tuple_constructor(
            PassboltUserTuple,
            subconstructors={
                'gpgkey': tuple_constructor(PassboltOpenPgpKeyTuple)
            }
        )(r.json()['body'])

        if isinstance(users, PassboltUserTuple): users = [users]
        return users

# ///////////////////////////////////////////////////////////////////////////////////

    def get_admins(self):
        return self.get_users(is_admin=True)

# ///////////////////////////////////////////////////////////////////////////////////

    def get_active_users(self):
        return self.get_users(is_active=True)

# ///////////////////////////////////////////////////////////////////////////////////

    def authenticate(self):
        verify_token = str(uuid.uuid4())

        login_challenge = {
            "version":"1.0.0",
            "domain": "https://10.221.221.105:27443",
            "verify_token" : verify_token,
            "verify_token_expiry" : str((datetime.datetime.now() + datetime.timedelta(minutes=2)).timestamp())
        }

        enc_login_challenge = self.gpg.encrypt(
            json.dumps(login_challenge),
            self.server_fingerprint,
            sign=self.gpg_fingerprint,
            passphrase=self.gpg_passphrase,
            always_trust=True,
        )

        login_payload = {
            'user_id': 'fe0ba7d4-dea7-43ac-ac15-c3d35da3231a',
            'challenge': str(enc_login_challenge)
        }

        login_response = self.http_session.post(self.server_url + '/auth/jwt/login.json', json=login_payload)
        self._check_passbolt_response(login_response)

        enc_challenge = login_response.json()['body']['challenge']
        decrypted_challenge = self.gpg.decrypt(enc_challenge, passphrase=self.gpg_passphrase)
        dec_challenge_json = json.loads(str(decrypted_challenge))

        if verify_token != dec_challenge_json['verify_token']: # todo: check and refactor
            raise ValueError(f"The verify_token returned by the server '{dec_challenge_json['verify_token']}' is different from the generated one '{verify_token}'")

        self.jwt_auth_token = dec_challenge_json['access_token']
        self.jwt_refresh_token = dec_challenge_json['refresh_token']
        self.http_session.headers.update({ 'Authorization': f'Bearer {self.jwt_auth_token}' })

        self.get_jwt_rsa_server_info()

# ///////////////////////////////////////////////////////////////////////////////////

    def import_server_public_key(self):
        r = self.http_session.get(f"{self.server_url}/auth/verify.json")
        self._check_passbolt_response(r)

        body = r.json()
        server_fingerprint = body['body']['fingerprint']
        server_keydata = body['body']['keydata']

        self.server_fingerprint = server_fingerprint
        self.gpg.import_keys(server_keydata)
        self.gpg.trust_keys(self.server_fingerprint, "TRUST_FULLY")

        return server_keydata


# ///////////////////////////////////////////////////////////////////////////////////

    def share_password(self, password_id, user_id):
        params = {
            "permissions": [{
                "aro": "User",
                "aro_foreign_key": "",
                "type": 1,
                "is_new": True,
            }],
            "secrets": [{
                "data":"x",
                "user_id" : user_id,
            }]
        }

        r = self.http_session.put(f"{self.server_url}/share/simulate/resource/{password_id}", params=params)
        self._check_passbolt_response(r)
        print(r.content)


    def get_aros(
        self,
        search_filter: Optional[str] = None,
        include_group_users: Optional[bool] = False,
        include_gpg_key: Optional[bool] = False,
        include_role: Optional[bool] = False,
    ):
        params = {}
        if search_filter: params['filter[search]'] = search_filter
        if include_group_users: params['contain[groups_users]'] = 1
        if include_gpg_key: params['contain[gpgkey]'] = 1
        if include_role: params['contain[role]'] = 1

        r = self.http_session.get(f"{self.server_url}/share/search-aros.json", params=params)
        self._check_passbolt_response(r)
        __import__('pprint').pprint(r.json()['body'])
        return



# -----------------------------------------------------------------------------------
    # todo: delete server and users keys
    # todo: get users
    # todo: get folders
    # todo: list_folder
    # todo: list_passwords
    # todo: share password with a user
