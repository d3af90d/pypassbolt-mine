import passboltapi
import urllib3

from passboltapi.schema import *

if __name__ == '__main__':
    # setup passbolt api object
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # Disable warnings about not checking server SSL certificate
    passbolt_api = passboltapi.PassboltAPI(config_path="config.ini")

    ok = passbolt_api.pmo(
        folder_to_search='folder_one',
        username_to_share='email2@deafgod.xyz',
        password_to_search='pass-descr-totp',
    )

    # if not ok:
    #     print('problems with pmo procedure')
