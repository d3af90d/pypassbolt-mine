import configparser, json, gnupg, requests, uuid, datetime, jwt, logging
from typing import List, Optional

from passboltapi.schema import *

class PassboltAPI():
    def __init__(
       self,
       config: Optional[str] = None,
       config_path: Optional[str]|None = None,
   ):
# ***********************************************************************************
#                               CONFIGURATION
# ***********************************************************************************
# ***********************************************************************************
        self.gpg                   = gnupg.GPG()
        self.user_fingerprint      = ''
        self.server_url            = ''
        self.server_fingerprint    = ''
        self.jwt_auth_token        = ''
        self.jwt_refresh_token     = ''
        self.server_jwt_public_key = ''
        self.config                = {}
        self.logger = logging.getLogger('pypassbolt-mine')

        # ----------------------------------
        # check supplied configuration
        # ----------------------------------
        # the dictionary config has precedence over the config_path
        # ----------------------------------
        if not config:
            if not config_path:
                raise ValueError("pypassbolt-mine: PassboltAPI class requires the 'config' or the 'config_path' parameter set.")

            self.config = configparser.ConfigParser()
            self.config.read_file(open(config_path))
            self.config = dict(self.config['passbolt'])
        else:
            self.config = config

        # ----------------------------------
        # read config
        # ----------------------------------
        self.server_url       = self.config['server']
        self.user_fingerprint = self.config['user_fingerprint'].upper().replace(' ', '')
        # todo: check if the key is already imported or not imported or not
        try:
            self.gpg_fingerprint = [i for i in self.gpg.list_keys() if i['fingerprint'] == self.user_fingerprint][0]['fingerprint']
        except IndexError:
            raise Exception("GPG public key could not be found. Check: gpg --list-keys")

        if self.user_fingerprint not in [i["fingerprint"] for i in self.gpg.list_keys(True)]:
            raise Exception("GPG private key could not be found. Check: gpg --list-secret-keys")

        self.gpg_passphrase   = self.config['passphrase']
        # todo: Check if passphrase is right

        # ----------------------------------
        # http session setup
        # ----------------------------------
        # todo: cleanup
        # ----------------------------------
        self.http_session = self.PassboltSession()
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
        self._authenticate()


# ***********************************************************************************
#                                 HTTP CLIENT
# ***********************************************************************************
# ***********************************************************************************

    class PassboltSession(requests.Session):
        def __init__(self) -> None:
            super().__init__()
            self.server_jwt_public_key = None
            self.passboltapi = None

        def _check_passbolt_response(self, response: requests.Response):
            if response.status_code != 200:
                raise requests.HTTPError(f"Unexpected status code ({response.status_code}) in response from {response.url}\nResponse: {response.content}", response=response)

            if "application/json" not in response.headers.get("Content-Type", ""):
                raise requests.HTTPError(f"Not a JSON response from {response.url}.\nResponse: {response}", response=response)

            body = response.json()
            if not {"header", "body"}.issubset(body.keys()):
                raise requests.HTTPError(f"Unexpected passbolt response: {body}", response=response)

            # todo
            if body['header']['status'] != 'success':
                raise requests.HTTPError(f"TODO", response=response)

        # todo: put check passbolt response method here

        def _is_session_valid(self, auth_header: str):
            # try:
            #     #todo: implement session check and refresh
            #     #todo: save server jwt public key
            #     #todo: add signature verification of the jwt
            #     # decoded = jwt.decode(JWT, options={'verify_signature': False}, algorithms=['RS256'])
            #     # print(decoded)
            # except Exception as e: raise e
            return

        def request(self, method, *args, **kwargs):
            if 'Authorization' in self.headers.keys():
                self._is_session_valid(str(self.headers['Authorization']))
            response = super().request(method, *args, **kwargs)
            self._check_passbolt_response(response)

            return response


    def _check_passbolt_response(self, response: requests.Response):
        if response.status_code != 200:
            raise requests.HTTPError(f"Unexpected status code ({response.status_code}) in response from {response.url}\nResponse: {response.content}", response=response)

        if "application/json" not in response.headers.get("Content-Type", ""):
            raise requests.HTTPError(f"Not a JSON response from {response.url}.\nResponse: {response}", response=response)

        body = response.json()
        if not {"header", "body"}.issubset(body.keys()):
            raise requests.HTTPError(f"Unexpected passbolt response: {body}", response=response)

        # todo
        if body['header']['status'] != 'success':
            raise requests.HTTPError(f"TODO", response=response)

# ***********************************************************************************
#                                 INTERNAL METHODS
# ***********************************************************************************
# ***********************************************************************************
    def _authenticate(self):
        verify_token = str(uuid.uuid4())

        # prepare the login challenge needed for authentication
        login_challenge = {
            "version":"1.0.0",
            "domain": "https://10.221.221.105:27443", # todo: remove hardcoded value
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

        self.api_get_jwt_rsa_server_info()


# ***********************************************************************************
#                            API METHODS
# ***********************************************************************************
# each following method is associated with a single REST endpoint based on the
#  passbolt documentation: https://www.passbolt.com/docs/api/
# ***********************************************************************************

# -----------------------------------------------------------------------------------
#                            AUTHENTICATION (JWT)
# -----------------------------------------------------------------------------------

    def api_get_server_public_GPG_key(self): return

    def api_get_server_jwks_info(self):
        return

    def api_login(self):
        return

    def api_logout(self):
        return

    def api_refresh_access_token(self):
        return

    def api_get_jwt_rsa_server_info(self):
        r = self.http_session.get(f"{self.server_url}/auth/jwt/rsa.json")
        self._check_passbolt_response(r)
        self.server_jwt_public_key = r.json()['body']['keydata']
        self.http_session.server_jwt_public_key = r.json()['body']['keydata']
        # print(self.http_session.server_jwt_public_key)

# -----------------------------------------------------------------------------------
#                                 AVATAR
# -----------------------------------------------------------------------------------
    def api_get_avatar_as_an_image(self): return
    # todo: very low priority. Maybe is the last thing

# -----------------------------------------------------------------------------------
#                                 COMMENTS
# -----------------------------------------------------------------------------------
    def api_update_comment(self): return
    def api_delete_comment(self): return
    def api_get_comment_for_resource(self): return
    def api_add_comment(self): return

# -----------------------------------------------------------------------------------
#                                 FAVORITES
# -----------------------------------------------------------------------------------
    def api_unset_favorite_resource(self): return
    def api_set_favorite_resource(self): return

# -----------------------------------------------------------------------------------
#                                  FOLDERS
# -----------------------------------------------------------------------------------

    def api_get_multiple_folders(
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
        https://www.passbolt.com/docs/api/#tag/Folders/operation/indexFolders
        '''
        ENDPOINT = f"{self.server_url}/folders.json"

        params = {}
        if search                    : params['filter[search]']              = search
        if include_children_resources: params['contain[children_resources]'] = 1
        if include_children_folders  : params['contain[children_folders]']   = 1
        if include_creator           : params['contain[creator]']            = 1
        if include_creator_profile   : params['contain[creator.profile]']    = 1
        if include_modifier          : params['contain[modifier]']           = 1
        if include_modifier_profile  : params['contain[modifier.profile]']   = 1

        r = self.http_session.get(ENDPOINT, params=params)
        self._check_passbolt_response(r)

        # check if this method raises an error if children_folder or resources are not requested
        folders = tuple_constructor(
            PassboltFolderTuple,
            subconstructors={
                "children_resources": tuple_constructor(PassboltResourceTuple),
                "children_folders"  : tuple_constructor(PassboltFolderTuple),
            }
        )(r.json()['body'])

        return folders

    def api_create_folder(self): return

    def api_get_folder(
        self,
        folder_id                       : PassboltFolderIdType,
        has_id                          : str  = '', #?
        include_children_resources      : bool = False,
        include_children_folders        : bool = False,
        include_creator                 : bool = False,
        include_creator_profile         : bool = False,
        include_modifier                : bool = False,
        include_modifier_profile        : bool = False,
        include_permission              : bool = False,
        include_permissions             : bool = False,
        include_permissions_user_profile: bool = False,
        include_permissions_group       : bool = False,
    ) -> PassboltFolderTuple:
        params = {}
        if include_children_resources: params['contain[children_resources]'] = 1
        if include_children_folders  : params['contain[children_folders]']   = 1
        if include_creator           : params['contain[creator]']            = 1
        if include_creator_profile   : params['contain[creator.profile]']    = 1
        if include_modifier          : params['contain[modifier]']           = 1
        if include_modifier_profile  : params['contain[modifier.profile]']   = 1

        r = self.http_session.get(f"{self.server_url}/folders/{folder_id}.json", params=params)
        self._check_passbolt_response(r)

        folder = tuple_constructor(
            PassboltFolderTuple,
            subconstructors={
                "children_resources": tuple_constructor(PassboltResourceTuple),
                "children_folders"  : tuple_constructor(PassboltFolderTuple),
            }
        )(r.json()['body'])

        return folder

    def api_update_folder(self): return
    def api_delete_folder(self): return

# -----------------------------------------------------------------------------------
#                                 GPG
# -----------------------------------------------------------------------------------
    def api_get_multiple_gpg_keys(self): return
    def api_get_gpg_key(self): return

# -----------------------------------------------------------------------------------
#                                 GROUPS
# -----------------------------------------------------------------------------------
    def api_get_multiple_groups(self)   : return
    def api_create_group(self)          : return
    def api_get_group(self)             : return
    def api_update_group(self)          : return
    def api_delete_group(self)          : return
    def api_dry_run_group_update(self)  : return
    def api_dry_run_group_deletion(self): return

# -----------------------------------------------------------------------------------
#                                 HEALTHCHECK
# -----------------------------------------------------------------------------------
    def api_get_healthcheck_info(self): return
    def api_is_passbolt_up(self): return

# -----------------------------------------------------------------------------------
#                                  MOVE
# -----------------------------------------------------------------------------------
    def api_move_element(self): return

# -----------------------------------------------------------------------------------
#                                   MFA
# -----------------------------------------------------------------------------------
    def api_check_mfa(self): return
    def api_attempt_mfa(self): return
    def api_get_mfa_requirements_info(self): return

# -----------------------------------------------------------------------------------
#                                PERMISSIONS
# -----------------------------------------------------------------------------------
    def api_get_resource_permissions(
        self,
        resource_id: str,
        include_group: Optional[bool] = False,
        include_user: Optional[bool] = False,
        include_user_profile: Optional[bool] = False,

    ) -> List[PassboltPermissionTuple]:
        '''
        https://www.passbolt.com/docs/api/#tag/Permissions/operation/indexPermissionsResource
        '''

        ENDPOINT = f"{self.server_url}/permissions/resource/{resource_id}.json"

        params = {}
        if include_group       : params['contain[group]']        = 1
        if include_user        : params['contain[user]']         = 1
        if include_user_profile: params['contain[user.profile]'] = 1

        r = self.http_session.get(ENDPOINT, params=params)

        permissions = tuple_constructor(
            PassboltPermissionTuple
        )(r.json()['body'])
        # print(r.json()['body'])

        return permissions


# -----------------------------------------------------------------------------------
#                                RESOURCES
# -----------------------------------------------------------------------------------

    def api_get_multiple_resources(
        self,
        with_secret: Optional[bool] = False,
        with_resource_type: Optional[bool] = False,
    ) -> List[PassboltResourceTuple]:
        params = {}
        r = self.http_session.get(f"{self.server_url}/resources.json", params=params)
        self._check_passbolt_response(r)
        resources = tuple_constructor(PassboltResourceTuple)(r.json()['body'])
        return resources

    def api_create_resource(
        self,
        name:str,
        username:str,
        uri:str,
        description,
        resource_type_id,
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

    def api_get_resource(self): return
    def api_update_resource(self): return
    def api_delete_resource(self): return

# -----------------------------------------------------------------------------------
#                              RESOURCE TYPES
# -----------------------------------------------------------------------------------
    def api_get_multiple_resource_types(self) -> List[PassboltResourceTypeTuple]:
        r = self.http_session.get(f"{self.server_url}/resource-types.json")
        self._check_passbolt_response(r)
        resource_types = tuple_constructor(PassboltResourceTypeTuple)(r.json()['body'])
        return resource_types

    def api_get_resource_type(self, resource_type_id) -> PassboltResourceTypeTuple | None:
        r = self.http_session.get(f"{self.server_url}/resource-types/{resource_type_id}.json")
        self._check_passbolt_response(r)

        # __import__('pprint').pprint(r.json()['body'])
        resource_type = tuple_constructor(
            PassboltResourceTypeTuple,
        )(r.json()['body'])

        return resource_type


# -----------------------------------------------------------------------------------
#                                 ROLES
# -----------------------------------------------------------------------------------
    def api_get_multiple_roles(self): return

# -----------------------------------------------------------------------------------
#                                 SECRETS
# -----------------------------------------------------------------------------------

    def api_get_user_secret_for_resource(
        self,
        resource_id: PassboltResourceIdType
    ) -> PassboltSecretTuple | None:
        '''
        https://www.passbolt.com/docs/api/#tag/Secrets/operation/viewSecret
        '''
        r = self.http_session.get(f"{self.server_url}/secrets/resource/{resource_id}.json")
        self._check_passbolt_response(r)
        # todo: check what happens when a resource does not exist
        secret: PassboltSecretTuple = tuple_constructor(PassboltSecretTuple)(r.json()['body'])
        return secret

# -----------------------------------------------------------------------------------
#                                  SHARES
# -----------------------------------------------------------------------------------

    def api_share_resource_or_folder(
        self,
        foreign_model: Literal['resource', 'folder'],
        foreign_id: PassboltResourceIdType,
        permissions: List[PassboltResourceIdType],
        secrets: List[PassboltSecretTuple],
    ):
        '''
        todo: ?add checks on permission and mismatches with secrets and permission?

        https://www.passbolt.com/docs/api/#tag/Shares/operation/updateShare
        '''

        ENDPOINT = f"{self.server_url}/share/{foreign_model}/{foreign_id}.json"

        params = {
            'permissions': [{k: v for k, v in p._asdict().items() if v is not None} for p in permissions],
            'secrets': [{k: v for k, v in s._asdict().items() if v is not None} for s in secrets],
        }
        print(params)

        # todo: capire se devo aggiungere anche i vecchi permessi
        # no, viene solo aggiunto, se il permesso e' nuovo
        r = self.http_session.put(ENDPOINT, json=params)

        # todo: check if specified user can decrypt the secrets

        # todo: add checks in case of error
        print(r.json()['body'])

        return

    def api_get_aros_for_sharing(
        self,
        search_filter       : Optional[str]  = None,
        include_group_users : Optional[bool] = False,
        include_gpgkey      : Optional[bool] = False,
        include_role        : Optional[bool] = False, # todo: To implement
    ):
        '''
        search_filter       : search for a specific user or group
        include_group_users : if True, include the users in the specified group in the response
        include_gpgkey      : if True, include the user gpg key in the response
        include_role        : if True, include the user role in the response

        https://www.passbolt.com/docs/api/#tag/Shares/operation/indexShareAros
        '''

        ENDPOINT = f"{self.server_url}/share/search-aros.json"

        params = {}
        if search_filter       : params['filter[search]']        = search_filter
        if include_group_users : params['contain[groups_users]'] = 1
        if include_gpgkey      : params['contain[gpgkey]']       = 1
        if include_role        : params['contain[role]']         = 1

        r = self.http_session.get(ENDPOINT, params=params)
        self._check_passbolt_response(r)

        aros : PassboltAroTuple = tuple_constructor(
            PassboltAroTuple,
            subconstructors={
                "gpgkey": tuple_constructor(PassboltOpenPgpKeyTuple)
            }
        )(r.json()['body'])

        return aros

    def api_simulate_share_resource_or_folder(
        self,
        foreign_model: Literal['resource', 'folder'],
        foreign_id: PassboltResourceIdType,
        permissions: List[PassboltResourceIdType],
        secrets: List[PassboltSecretTuple],
    ):
        ENDPOINT = f"{self.server_url}/share/simulate/{foreign_model}/{foreign_id}.json"

        params = {
            'permissions': [{k: v for k, v in p._asdict().items() if v is not None} for p in permissions],
            'secrets': [{k: v for k, v in s._asdict().items() if v is not None} for s in secrets],
        }
        print(params)

        # todo: capire se devo aggiungere anche i vecchi permessi
        # no, viene solo aggiunto, se il permesso e' nuovo
        r = self.http_session.post(ENDPOINT, json=params)

        # todo: check if specified user can decrypt the secrets

        # todo: add checks in case of error
        print(r.json()['body'])

        return
        return

# -----------------------------------------------------------------------------------
#                                  USERS
# -----------------------------------------------------------------------------------

    def api_get_multiple_users(
        self,
        search                : Optional[str]                          = None,
        has_groups            : Optional[List[PassboltGroupIdType]]    = None,
        has_access            : Optional[List[PassboltResourceIdType]] = None,
        is_admin              : Optional[bool]                         = None,
        is_active             : Optional[bool]                         = None,
        include_last_logged_in: Optional[bool]                         = None,
        include_group_users   : Optional[bool]                         = None,
        include_gpgkey        : Optional[bool]                         = None,
        include_profile       : Optional[bool]                         = None,
        include_role          : Optional[bool]                         = None,
    ) -> List[PassboltUserTuple]:
        '''
        Returns a list of used filtered with criteria based on the arguments provided

        search: is set, search only for users based on the provided string
        has_groups: list of group uuids - returns users belonging to the groups provided
        has_access: list of res?
        is_admin: if True, returns only administrators
        is_active: if True, returns only active users
        '''
        ENDPOINT = f"{self.server_url}/users.json"

        params = {}
        if search    : params['filter[search]']     = search
        if has_groups: params['filter[has-groups]'] = has_groups
        if has_access: params['filter[has-access]'] = has_access
        if is_admin  : params['filter[is-admin]']   = True
        if is_active : params['filter[is-active]']  = True

        if include_last_logged_in: params['contain[last_logged_in]'] = 1
        if include_group_users   : params['contain[group_users]']    = 1
        if include_gpgkey        : params['contain[gpgkey]']         = 1
        if include_profile       : params['contain[profile]']        = 1
        if include_role          : params['contain[role]']           = 1

        r = self.http_session.get(ENDPOINT, params=params)
        # self._check_passbolt_response(r)

        users = tuple_constructor(
            PassboltUserTuple,
            subconstructors={
                'gpgkey': tuple_constructor(PassboltOpenPgpKeyTuple)
            }
        )(r.json()['body'])

        if isinstance(users, PassboltUserTuple): users = [users]
        return users

    def api_create_user(self): return

    def api_get_user(
        self,
        user_id: str
    ) -> PassboltUserTuple: 
        '''
        https://www.passbolt.com/docs/api/#tag/Users/operation/viewUser
        '''
        ENDPOINT = f"{self.server_url}/users/{user_id}.json"
        r = self.http_session.get(ENDPOINT)

        user : PassboltUserTuple = tuple_constructor(
            PassboltUserTuple,
            subconstructors={
                'gpgkey': tuple_constructor(PassboltOpenPgpKeyTuple)
            }
        )(r.json()['body'])

        return user

    def api_update_user(self): return
    def api_delete_user(self): return
    def api_dry_run_delete_user(self): return

# ***********************************************************************************
#                              HELPER METHODS
# ***********************************************************************************
# ***********************************************************************************

    def pmo(
        self,
        folder_to_search: str,
        password_to_search: str,
        username_to_share: str,
    ) -> bool:

        # get info on the specified folder
        chosen_folder = self.api_get_multiple_folders(
            search=folder_to_search,
            include_children_resources=True,
            include_children_folders=True,
        )

        if len(chosen_folder) == 0:
            print('folder not found')
            return False

        # i get the first of the list
        # if the name is not exactly specified idk how the list is ordered or if its deterministic
        chosen_folder = chosen_folder[0]

        # get all resources in the specifed folders and its subfolders
        folders_to_scan = [chosen_folder.id]
        resources = []
        while folders_to_scan:
            search_id = folders_to_scan.pop()
            f = self.api_get_folder(
                search_id,
                include_children_folders=True,
                include_children_resources=True
            )
            for cf in f.children_folders: folders_to_scan.append(cf.id)
            for cr in f.children_resources: resources.append(cr)

        # check if the provided password is in the found resources
        pass_to_share = next((r for r in resources if r.name == password_to_search), None)

        # if the password does not exist, we need to create it
        if not pass_to_share:
            # todo: create the password
            chosen_password : PassboltResourceTuple = self.create_random_pass_and_descr()
            return None

        rts = self.api_get_multiple_resource_types()
        print(rts)
        # at this point the password exist
        # we just need to share it with the specified user or group
        # let's search the aro for sharing

        # self.share_resource(chosen_password, 'email02@deafgod.xyz')

        return

    def create_random_pass_and_descr(self) -> PassboltResourceTuple:
        # Create the right Payloas
        # call the api endpoitn for creating a resource

        return

    def is_aro_a_group( self, aro: PassboltAroTuple,):
        return True if aro.user_count else False

    def create_secret(
        self,
        resource_type: str,
        password: str,
        description: str,
    ):
        return


    def check_new_properties_for_resource(
        self,
        prop: dict,
        resource: PassboltResourceTuple
    ) -> bool:

        def check_prop_type(prop_def, prop_value):
            match prop_def['type']:
                case 'string':
                    if len(prop_value) > prop_def['maxLength']:
                        print(f"string field too long")
                        exit(1)
                case 'null':
                    print('check if its empty')
                case _:
                    print('other type')

            return

        def find_right_definition(prop_value, type_list) -> dict | None:
            prop_mapping = {
                'str': 'string',
                'NoneType': 'null'
            }

            prop_type = prop_mapping.get(type(prop_value).__name__)
            if not prop_type: return None

            return next((t for t in type_list if t['type'] == prop_type), None)


        res_type = self.api_get_resource_type(resource.resource_type_id)
        # print(res_type.definition)

        rdef = json.loads(res_type.definition)
        resource_def = rdef['resource']

        # check if the required fields are present
        required_fields = resource_def['required']
        missing_fields = [k for k in required_fields if k not in prop]
        if missing_fields:
            print('there are missing fields for the specified resource type')
            return None

        # print(f"{missing_fields=}")

        type_properties = resource_def['properties']

        print(f"{resource_def=}")
        print(f"{type_properties=}")
        for k in type_properties:
            if k not in prop: continue
            prop_def = type_properties[k]
            # print(f"{k=}")
            # print(f"{prop_def=}")
            if 'anyOf' in prop_def:
                prop_def = find_right_definition(prop[k], prop_def['anyOf'])
            check_prop_type(prop_def, prop[k])
        # check if the passed properties respect the requirement

        secret_def = rdef['secret']
        __import__('pprint').pprint(resource_def)
        __import__('pprint').pprint(secret_def)
        # check type of resource

        return True

    def process_resource_type(
        self,
        rt: PassboltResourceTypeTuple
    ):
        # use the definition field to check for required fields and stuff
        __import__('pprint').pprint(json.loads(rt.definition))

        # first check for resource properties
        # check secret properties

        return

    def import_public_keys(self, trustlevel="TRUST_FULLY"):
        users = self.get_active_users()
        for user in users:
            self.gpg.import_keys(user.gpgkey.armored_key)
            self.gpg.trust_keys(user.gpgkey.fingerprint, trustlevel)


    def _encrypt_secret(
        self,
        secret_str: str,
        user_list: List[PassboltUserTuple],
    ):
        return [
            {
                "user_id": user.id,
                "data": str(self.gpg.encrypt(data=secret_str, recipients=user.gpgkey.fingerprint, always_trust=True))
            } for user in user_list
        ]

    def share_resource(
        self,
        resource: PassboltResourceTuple,
        user_or_group: str
    ):
        '''
        return bool? Or
        '''

        # lets first implement for a single user
        # print(resource)
        # print(aro)
        # print(type(resource))
        # print(type(aro))
        # print(aro.gpgkey.fingerprint)

        # 1 - find aro associated with the user
        chosen_aro : PassboltAroTuple = self.api_get_aros_for_sharing(
            search_filter=user_or_group,
            include_gpgkey=True,
            include_group_users=True,
        )[0]
        # print(f"\n\n==================\n")
        # print(chosen_aro)

        chosen_user : PassboltUserTuple = self.api_get_user(chosen_aro.id)
        # print(f"\n\n==================\n")
        # print(chosen_user)

        is_group = self.is_aro_a_group(chosen_aro)

        # print(f"\n\n==================\n")
        # print(is_group)

        permissions = self.api_get_resource_permissions(
            resource.id,
            include_group=True,
            include_user=True,
        )
        print(f"\n\n==================\n")
        print(permissions)

        # check if permission for user exists
        # if exist, exit (for now)
        for p in permissions:
            if p.aro_foreign_key == chosen_aro.id:
                print('permission for user exists')
                return

        # create payload for sharing
        if is_group:
            # create permission and user_list for group
            pass
        else:
            # create permission and list for user
            # pp = {
            #     'aro':'User',
            #     'aro_foreign_key': chosen_aro.id,
            #     'type': PassboltPermissionType.READ,
            #     'is_new': True,
            # }
            # pp_tuple = tuple_constructor(PassboltPermissionTuple)(pp)
            pass

        # after creating the permission we can create the list of secretTuples

        # after creating the list of permissions and the list of tuple, we can create the sharingPayloadTuple? or just a dictionary
        # todo: capire se le permission vengono sovrascritte dalla mia post o solo aggiunte

        enc_sec : PassboltSecretTuple = self.api_get_user_secret_for_resource(resource.id)
        dec_sec = str(self.gpg.decrypt(enc_sec.data, passphrase=self.gpg_passphrase))
        print(dec_sec)


        user_list = [chosen_user]
        # create user permissions
        params = {
            "permissions": [
                 {
                    'aro':'User',
                    'aro_foreign_key': chosen_aro.id,
                    'type': PassboltPermissionType.READ,
                    'is_new': True,
                }
            ],
            "secrets": [
                {
                    "user_id": user.id,
                    "data": str(self.gpg.encrypt(data=dec_sec, recipients=user.gpgkey.fingerprint, always_trust=True))
                } for user in user_list
            ]
            # "secrets": self._encrypt_secret(sec_str, users_list)[{
            #"secrets": self._encrypt_secret(),
        }
        print(f"\n\n==================\n")
        print(params)

        p_t : List[PassboltPermissionTuple] = tuple_constructor(PassboltPermissionTuple)(
             [{
                'aro':'User',
                'aro_foreign_key': chosen_aro.id,
                'type': PassboltPermissionType.READ.value,
                'is_new': True,
            }]
        )

        user_list = [chosen_user]
        secrets = [
            {
                "user_id": user.id,
                "data": str(self.gpg.encrypt(data=dec_sec, recipients=user.gpgkey.fingerprint, always_trust=True))
            } for user in user_list
        ]
        s_t : List[PassboltSecretTuple] = tuple_constructor(PassboltSecretTuple)(secrets)

        print(type(p_t))
        print(type(s_t))
        self.api_share_resource_or_folder(
            'resource',
            resource.id,
            p_t,
            s_t
        )

        exit(1)

        #  create permissions
        # share the resource

        # params = {
        #     "permissions": [{
        #         "aro": "User",
        #         "aro_foreign_key": "",
        #         "type": 1,
        #         "is_new": True,
        #     }],
        #     # "secrets": self._encrypt_secret(sec_str, users_list)[{
        #     "secrets": [{
        #         "data":"x",
        #         "user_id" : user_id,
        #     }]
        # }
        exit(1)


        return
    def get_admins(self):
        return self.api_get_multiple_users(is_admin=True)


    def get_active_users(self):
        return self.api_get_multiple_users(is_active=True)

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

    def simulate_sharing_resource(
        self,
        foreign_model: str,
        foreign_id: str,
        permissions: List[PassboltPermissionTuple],
        secrets: List[dict],
    ):
        '''
        Voglio che il valore dei parametri sia gia' pronto
        Faccio solo icheck che siano ben formati, ma devono gia' essere passati pronti
        Metodi che fanno l'heavy lifting delle operazioni pre sharing li faccio a parte.
        Voglio che ogni endpoint dell'api abbia il proprio metodo in modo che poi in altri metodi ci siano le operazioni non direttamente mappate a un endpoint API
        '''

        if foreign_model not in ['resource', 'folder']:
            print('error')
            exit(1)

        secrets = []
        payload = {
            'permissions': [p._asdict() for p in permissions],
            'secrets': secrets,
        }

        r = self.http_session.post(f"{self.server_url}/share/simulate/{foreign_model}/{foreign_id}.json", json=payload)
        self._check_passbolt_response(r)
        print(r.json()['body'])

        return

    def share_password(self, password_id, user_id):
        params = {
            "permissions": [{
                "aro": "User",
                "aro_foreign_key": "",
                "type": 1,
                "is_new": True,
            }],
            # "secrets": self._encrypt_secret(sec_str, users_list)[{
            "secrets": [{
                "data":"x",
                "user_id" : user_id,
            }]
        }

        r = self.http_session.put(f"{self.server_url}/share/simulate/resource/{password_id}", params=params)
        self._check_passbolt_response(r)
        print(r.content)


