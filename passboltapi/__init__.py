import configparser, json, gnupg, requests, uuid, datetime, jwt
from typing import List, Optional

from passboltapi.schema import *

JWT = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovLzEwLjIyMS4yMjEuMTA1OjI3NDQzLyIsInN1YiI6ImZlMGJhN2Q0LWRlYTctNDNhYy1hYzE1LWMzZDM1ZGEzMjMxYSIsImV4cCI6MTc0MDQzMjUwOH0.PkA5yvQD8gDx3R-fNWQgRDG2aVik70Wg1RY2GbYkPs5aXpGr8Dt2ahN1p2fi0AfIhosGWser1SHer0czvytp1qpVyql-e4pdosnxrqT7vLjRQvQfzn5keSIyNhB2upEUkYWRb6ogpd-du3aYOjSNBE1PxckDi14WGTmK1GMF5jpiPyae8dvg7CUTTrYCrszRlFknlNr2r5pOLbcWO-p-mui77oykCz2VmGHlSD2UCYsQopIjJZNmHel6LQeCzucI3rhv0QgUJ4ZKstrRS17xC9HQoiGlpLYI5s_lvMUeYUJlRn7PKcHwkDd1mplZodXmLAgHvCKzzBgUxh11D7J5Z8rEq24q9PFADwrwXydCpipSUW21JHomP4x3FgBlQ6JA9f4JqSc8RYe7ZOKPrGv4zq9um2ECs94ZUbQFZ4b3Sqs1UTmzaal14C_cSlRbzl2G1ngkuZ9YbJGZ_pw3WWi4TItATBAy6NqiM5KPaI4gZheBmt3QinBm9iC17y9A_AMBUGijpBIaDMOWfNzwvhB2zrrrJysuZI4c5hUJg8LCNV8NVmgPJflQJmHfgb3OSAjb9YhNyQErH5J_fChNfKXJeBrRJVJGwr8kHly7TWaQo8zIbi_k9pwRL2WN3MVGjpAlfjgDslhluk5LfL5oOStuGyE4xtSAoXJONRotiP7JNmc'

class PassboltSession(requests.Session):
    def __init__(self) -> None:
        super().__init__()
        self.server_jwt_public_key = None

    def _is_session_valid(self, auth_header: str):
        try:
            #todo: implement session check and refresh
            #todo: save server jwt public key
            #todo: add signature verification of the jwt
            decoded = jwt.decode(JWT, options={'verify_signature': False}, algorithms=['RS256'])
            # print(decoded)
        except Exception as e: raise e
        return

    def request(self, method, *args, **kwargs):
        if 'Authorization' in self.headers.keys():
            self._is_session_valid(str(self.headers['Authorization']))
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
        # check config todo
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
        # read config todo
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
        # http session setup - todo
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
            raise requests.HTTPError(f"TODO", response=response)

# ///////////////////////////////////////////////////////////////////////////////////
#                            AUTHENTICATION (JWT)
# ///////////////////////////////////////////////////////////////////////////////////

    def get_jwt_rsa_server_info(self):
        r = self.http_session.get(f"{self.server_url}/auth/jwt/rsa.json")
        self._check_passbolt_response(r)
        self.server_jwt_public_key = r.json()['body']['keydata']
        self.http_session.server_jwt_public_key = r.json()['body']['keydata']
        # print(self.http_session.server_jwt_public_key)

# ///////////////////////////////////////////////////////////////////////////////////
#                                 SECRET
# ///////////////////////////////////////////////////////////////////////////////////

    def get_secret( self, resource_id: PassboltResourceIdType):
        r = self.http_session.get(f"{self.server_url}/secrets/resource/{resource_id}.json")
        self._check_passbolt_response(r)
        secret = tuple_constructor( PassboltSecretTuple)(r.json()['body'])
        return secret

# ///////////////////////////////////////////////////////////////////////////////////
#                                 RESOURCES
# ///////////////////////////////////////////////////////////////////////////////////

    def get_resources(
        self,
        with_secret: Optional[bool] = False,
        with_resource_type: Optional[bool] = False,
    ) -> List[PassboltResourceTuple]:
        params = {}
        r = self.http_session.get(f"{self.server_url}/resources.json", params=params)
        self._check_passbolt_response(r)
        resources = tuple_constructor(PassboltResourceTuple)(r.json()['body'])
        return resources

    def create_resource(
        self,
        name,
        password,
        description,
        resource_type_id,
        username="",
        uri="",
        user_id="",
        folder_parent_id="",
        expired="",
    ):
        # todo: add checks based on the 'definition' field of the resource type for bot properties and secret

        data = {
            "password": password,
            "description": description,
        }
        secrets = {
            "data": str(
                self.gpg.encrypt(
                    json.dumps(data),
                    self.gpg_fingerprint,
                    sign=self.gpg_fingerprint,
                    passphrase=self.gpg_passphrase,
                    always_trust=True)
                ),
            # "user_id": "0a491630-958a-4254-becc-f6902d1404d0",
            # "resource_id": "",
        }
        print(json.dumps(secrets))

        payload = {
            "resource_type_id": resource_type_id,
            "secrets": [secrets],
            "name": name,
            "username": "admin@deafgod.xyz",
            "uri": "https://example.com",
        }

        r = self.http_session.post(f"{self.server_url}/resources.json", json=payload)
        self._check_passbolt_response(r)

        created_resource = tuple_constructor(
            PassboltResourceTuple,
            subconstructors={
                "permission": tuple_constructor(PassboltPermissionTuple),
            }
        )(r.json()['body'])

        return created_resource

# ///////////////////////////////////////////////////////////////////////////////////
#                               RESOURCES TYPES
# ///////////////////////////////////////////////////////////////////////////////////

    def get_resource_types(self) -> List[PassboltResourceTypeTuple]:
        r = self.http_session.get(f"{self.server_url}/resource-types.json")
        self._check_passbolt_response(r)
        resource_types = tuple_constructor(PassboltResourceTypeTuple)(r.json()['body'])
        return resource_types

    def get_resource_type(self, resource_type_id):
        return

# ///////////////////////////////////////////////////////////////////////////////////
#                                  FOLDERS
# ///////////////////////////////////////////////////////////////////////////////////

    def get_multiple_folders(
        self,
        has_id: str = '',
        has_parent: str = '',
        search: str = '',
        include_children_resources: bool = False,
        include_children_folders: bool = False,
        include_creator: bool = False,
        include_creator_profile: bool = False,
        include_modifier: bool = False,
        include_modifier_profile: bool = False,
        include_permission: bool = False,
        include_permissions: bool = False,
        include_permissions_user_profile: bool = False,
        include_permissions_group: bool = False,
    ) -> List[PassboltFolderTuple]:
        '''
        docs
        '''
        params = {}
        if search: params['filter[search]'] = search
        if include_children_resources: params['contain[children_resources]'] = 1
        if include_children_folders: params['contain[children_folders]'] = 1
        if include_creator: params['contain[creator]'] = 1
        if include_creator_profile: params['contain[creator.profile]'] = 1
        if include_modifier: params['contain[modifier]'] = 1
        if include_modifier_profile: params['contain[modifier.profile]'] = 1

        r = self.http_session.get(f"{self.server_url}/folders.json", params=params)
        self._check_passbolt_response(r)

        folders = tuple_constructor(
            PassboltFolderTuple,
            subconstructors={
                "children_resources": tuple_constructor(PassboltResourceTuple),
                "children_folders": tuple_constructor(PassboltFolderTuple),
            }
        )(r.json()['body'])

        return folders

    # def create_folder(self):

    def get_folder(
        self,
        folder_id: PassboltFolderIdType,
        has_id: str = '', #?
        include_children_resources: bool = False,
        include_children_folders: bool = False,
        include_creator: bool = False,
        include_creator_profile: bool = False,
        include_modifier: bool = False,
        include_modifier_profile: bool = False,
        include_permission: bool = False,
        include_permissions: bool = False,
        include_permissions_user_profile: bool = False,
        include_permissions_group: bool = False,
    ) -> PassboltFolderTuple:
        params = {}
        if include_children_resources: params['contain[children_resources]'] = 1
        if include_children_folders: params['contain[children_folders]'] = 1
        if include_creator: params['contain[creator]'] = 1
        if include_creator_profile: params['contain[creator.profile]'] = 1
        if include_modifier: params['contain[modifier]'] = 1
        if include_modifier_profile: params['contain[modifier.profile]'] = 1

        r = self.http_session.get(f"{self.server_url}/folders/{folder_id}.json", params=params)
        self._check_passbolt_response(r)


        folder = tuple_constructor(
            PassboltFolderTuple,
            subconstructors={
                "children_resources": tuple_constructor(PassboltResourceTuple),
                "children_folders": tuple_constructor(PassboltFolderTuple),
            }
        )(r.json()['body'])

        return folder

    # def update_folder(self):
    # def delete_folder(self):

# ///////////////////////////////////////////////////////////////////////////////////
#                                  SHARE
# ///////////////////////////////////////////////////////////////////////////////////
    def share_resource(
        self,
        resource_id: PassboltResourceIdType,
    ):
        return

# ///////////////////////////////////////////////////////////////////////////////////
#                                  USERS
# ///////////////////////////////////////////////////////////////////////////////////

    def get_users(
        self,
        include_last_logged_in: Optional[int] = None,
        search: Optional[str] = None,
        has_groups: Optional[List[PassboltGroupIdType]]    = None,
        has_access: Optional[List[PassboltResourceIdType]] = None,
        is_admin: Optional[bool]  = None,
        is_active: Optional[bool] = None,
    ) -> List[PassboltUserTuple]:
        '''
        Returns a list of used filtered with criteria based on the arguments provided

        search: is set, search only for users based on the provided string
        has_groups: list of group uuids - returns users belonging to the groups provided
        has_access: list of res?
        is_admin: if True, returns only administrators
        is_active: if True, returns only active users
        '''
        params = {}
        # 5 contains todo:
        if include_last_logged_in: params['contain[last_logged_in]'] = 1
        # 5 filters
        if search: params['filter[search]'] = search
        if has_groups: params['filter[has-groups]'] = has_groups # todo test
        if has_access: params['filter[has-access]'] = has_access # todo test
        if is_admin: params['filter[is-admin]']   = True
        if is_active: params['filter[is-active]'] = True

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

# -----------------------------------------------------------------------------------

    def get_admins(self):
        return self.get_users(is_admin=True)

# -----------------------------------------------------------------------------------

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


    def search_aros(
        self,
        search_filter       : Optional[str]  = None,
        include_group_users : Optional[bool] = False,
        include_gpgkey      : Optional[bool] = False,
        include_role        : Optional[bool] = False, # To implement
    ):
        params = {}
        if search_filter       : params['filter[search]']        = search_filter
        if include_group_users : params['contain[groups_users]'] = 1
        if include_gpgkey      : params['contain[gpgkey]']       = 1
        if include_role        : params['contain[role]']         = 1

        r = self.http_session.get(f"{self.server_url}/share/search-aros.json", params=params)
        self._check_passbolt_response(r)

        aros = tuple_constructor(
            PassboltAroTuple,
            subconstructors={
                "gpgkey": tuple_constructor(PassboltOpenPgpKeyTuple)
            }
        )(r.json()['body'])

        return aros
