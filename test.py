import passboltapi
import urllib3

if __name__ == '__main__':
    # Disable warnings about not checking server SSL certificate
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # passbolt_api_old = passboltapi.PassboltAPIOld(
    #     config_path="config.ini",
    #     new_keys=True,
    #     ssl_verify=False # anche se ho specificato False, ho dovuto modificare il codice della libreria per non controllare i certificati ssl
    # )
    # passbolt_api_old.get_server_public_key()
    # passbolt_api_old.authenticate()
    # passbolt_api_old.list_users()

    # config = {
    #     "passbolt": {
    #         "server": "https://10.221.221.105:27443",
    #         "server_public_key_file": "/home/user/dev/d3af90d-github/passbolt-api-mine/data/server.pub",
    #         "user_fingerprint": "0BC8 8428 5147 1ACA 6EFA ABC2 6FB8 4AB4 AB00 6CA9",
    #     }
    # }
    #passbolt_api = passboltapi.PassboltAPI(config=config)

    passbolt_api = passboltapi.PassboltAPI(config_path="config.ini")
    folders = passbolt_api.get_folders(include_children_resources=True, search_filter='2024')
    # for f in folders:
    #     for r in f.children_resources:
    #         print(r.name)

    #passbolt_api.get_users(is_admin=True, is_active=True)

    resources = passbolt_api.get_resources()
    passbolt_api.get_aros()
    # for r in resources:
    #     print(r.name)
    #
    # passbolt_api.get_jwt_rsa_server_info()
    # __import__('pprint').pprint(resources)
