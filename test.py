import time

import passboltapi
import urllib3


def get_my_passwords(passbolt_obj):
    result = list()
    for i in passbolt_obj.get(url="/resources.json?api-version=v2")["body"]:
        result.append({
            "id": i["id"],
            "name": i["name"],
            "username": i["username"],
            "uri": i["uri"]
        })
        print(i)
    for i in result:
        resource = passbolt_obj.get(
            "/secrets/resource/{}.json?api-version=v2".format(i["id"]))
        i["password"] = passbolt_obj.decrypt(resource["body"]["data"])
    print(result)


def get_passwords_basic():
    # A simple example to show how to retrieve passwords of a user.
    # Note the config file is placed in the project directory.
    passbolt_obj = passboltapi.PassboltAPI(config_path="config.ini")
    result = list()
    for i in passbolt_obj.get(url="/resources.json?api-version=v2")["body"]:
        result.append({
            "id": i["id"],
            "name": i["name"],
            "username": i["username"],
            "uri": i["uri"]
        })
        print(i)
    for i in result:
        resource = passbolt_obj.get(
            "/secrets/resource/{}.json?api-version=v2".format(i["id"]))
        i["password"] = passbolt_obj.decrypt(resource["body"]["data"])
    print(result)
    passbolt_obj.close_session()

    # Or using context managers
    # with passboltapi.PassboltAPI(config_path="config.ini") as passbolt:
    #     get passwords....


if __name__ == '__main__':
    # Disable warnings about not checking server SSL certificate
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    passbolt_api = passboltapi.PassboltAPI(
        config_path="config.ini",
        new_keys=True,
        ssl_verify=False # anche se ho specificato False, ho dovuto modificare il codice della libreria per non controllare i certificati ssl
    )
    passbolt_api.get_server_public_key()
    passbolt_api.authenticate()
    passbolt_api.list_users()
