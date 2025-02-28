import passboltapi
import urllib3

if __name__ == '__main__':
    # setup passbolt api object
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) # Disable warnings about not checking server SSL certificate
    passbolt_api = passboltapi.PassboltAPI(config_path="config.ini")

    # search for user to share the password with
    user_to_search = 'email00@deafgod.xyz'
    chosen_user = passbolt_api.get_users(search=user_to_search)[0]

    # search in the specific folder
    folder_name = 'folder_one'
    chosen_folder = passbolt_api.get_multiple_folders(
        search=folder_name,
        include_children_resources=True,
        include_children_folders=True,
    )[0]

    search_folders = [chosen_folder.id]
    resources = []
    while search_folders:
        search_id = search_folders.pop()
        print(f"[+] Processing: {search_id}")
        f = passbolt_api.get_folder(
            search_id,
            include_children_folders=True,
            include_children_resources=True
        )
        for cf in f.children_folders:
            search_folders.append(cf.id)
        for cr in f.children_resources:
            resources.append(cr)
        
    # print([r.name for r in resources])

    # define password to search
    name = '2024 - Kaleyra - KAL-HNS-240011_7'
    chosen_pass = next((r for r in resources if r.name == name), None)

    if not chosen_pass:
        print('pass not found')
        # create the password and share it
        pass
    else:
        print('pass found')
        pass
        # just share with the specified user

    aros = passbolt_api.search_aros(
        include_gpgkey=True,
        include_group_users=True,
    )
    print(aros)

    #passbolt_api.get_secret(pass_found.id)

    # update resource

    # new_pass = passbolt_api.create_resource(
    #     name="again-name-00",
    #     password="password",
    #     description="from script",
    #     resource_type_id=password_and_description_res_type.id,
    # )

    # Share resource

    # resource_types = passbolt_api.get_resource_types()
    # pass_desc_type = next((rt for rt in resource_types if rt.slug == 'password-and-description'), None)
