from enum import Enum
from typing import List, Mapping, NamedTuple, Optional, Union, TypeAlias, Literal

PassboltFolderIdType       : TypeAlias = str
PassboltResourceIdType     : TypeAlias = str
PassboltResourceTypeIdType : TypeAlias = str
PassboltUserIdType         : TypeAlias = str
PassboltRoleIdType         : TypeAlias = str
PassboltOpenPgpKeyIdType   : TypeAlias = str
PassboltGroupIdType        : TypeAlias = str
PassboltSecretIdType       : TypeAlias = str
PassboltPermissionIdType   : TypeAlias = str
PassboltDateTimeType       : TypeAlias = str
PassboltFavoriteDetailsType: TypeAlias = dict


class PassboltResourceType(Enum):
    PASSWORD                  = 1
    PASSWORD_WITH_DESCRIPTION = 2

class PassboltPermissionType(Enum):
    READ   = 1
    UPDATE = 7
    OWNER  = 15

class PassboltSecretTuple(NamedTuple):
    user_id    : PassboltUserIdType
    data       : str
    id         : Optional[PassboltSecretIdType] = None
    resource_id: Optional[PassboltResourceIdType] = None
    created    : Optional[PassboltDateTimeType] = None
    modified   : Optional[PassboltDateTimeType] = None

class PassboltPermissionTuple(NamedTuple):
    aro            : Literal["User", "Group"]
    aro_foreign_key: Union[PassboltUserIdType, PassboltGroupIdType]
    type           : int
    delete         : Union[None, bool]                                         = None
    is_new         : Union[None, bool]                                         = None
    aco            : Union[None, Literal["Resource", "Folder"]]                = None
    aco_foreign_key: Union[None, PassboltResourceIdType, PassboltFolderIdType] = None
    id             : Union[None, PassboltPermissionIdType]                     = None
    created        : Union[None,PassboltDateTimeType]                          = None
    modified       : Union[None, PassboltDateTimeType]                         = None
    group          : Union[None, "PassboltGroupTuple"]                         = None
    user           : Union[None, "PassboltUserTuple"]                          = None


class PassboltOpenPgpKeyTuple(NamedTuple):
    id         : PassboltOpenPgpKeyIdType
    user_id    : PassboltUserIdType
    armored_key: str
    created    : PassboltDateTimeType
    key_created: PassboltDateTimeType
    bits       : int
    deleted    : bool
    modified   : PassboltDateTimeType
    key_id     : str
    fingerprint: str
    type       : Literal["RSA", "ELG", "DSA", "ECDH", "ECDSA", "EDDSA"]
    expires    : PassboltDateTimeType


class PassboltUserTuple(NamedTuple):
    id             : PassboltUserIdType
    created        : PassboltDateTimeType
    active         : bool
    deleted        : bool
    modified       : PassboltDateTimeType
    username       : str
    role_id        : PassboltRoleIdType
    profile        : dict
    last_logged_in : PassboltDateTimeType
    role           : Optional[dict]                    = None
    gpgkey         : Optional[PassboltOpenPgpKeyTuple] = None


class PassboltResourceTuple(NamedTuple):
    id               : PassboltResourceIdType
    created          : PassboltDateTimeType
    created_by       : PassboltUserIdType
    deleted          : bool
    description      : str
    modified         : PassboltDateTimeType
    modified_by      : PassboltUserIdType
    name             : str
    uri              : str
    username         : str
    resource_type_id : PassboltResourceIdType
    folder_parent_id : PassboltFolderIdType
    creator          : Union[None, PassboltUserTuple]           = None
    favorite         : Union[None, PassboltFavoriteDetailsType] = None
    modifier         : Union[None, PassboltUserTuple]           = None
    permission       : Union[PassboltPermissionTuple]           = None


class PassboltResourceTypeDefinitionTuple(NamedTuple):
    resource: str
    secret: str

class PassboltResourceTypeTuple(NamedTuple):
    id: str
    slug        : str
    name        : str
    description : str
    definition  : PassboltResourceTypeDefinitionTuple
    created     : str
    modified    : str

class PassboltAroTuple(NamedTuple):
    id           : str
    deleted      : bool
    created      : str
    modified     : str
    groups_users : Optional[str] = None

    # user aro
    active   : Optional[bool] = None
    disabled : Optional[bool] = None
    role_id  : Optional[str] = None
    username : Optional[str] = None
    profile  : Optional[str] = None
    gpgkey   : Optional[PassboltOpenPgpKeyTuple] = None
    role     : Optional[str] = None
    last_logged_in : Optional[str] = None

    # group aro
    name       : Optional[str] = None
    user_count : Optional[int] = None
    created_by : Optional[str] = None
    modified_by: Optional[str] = None
    my_group_user : Optional[str] = None


class PassboltFolderTuple(NamedTuple):
    id                 : PassboltFolderIdType
    name               : str
    created            : PassboltDateTimeType
    modified           : PassboltDateTimeType
    created_by         : PassboltUserIdType
    modified_by        : PassboltUserIdType
    folder_parent_id   : PassboltFolderIdType
    personal           : bool
    permissions        : List[PassboltPermissionTuple]  =  []
    children_resources : List[PassboltResourceTuple]    =  []
    children_folders   : List["PassboltFolderTuple"]    =  []


class PassboltGroupTuple(NamedTuple):
    id: PassboltGroupIdType
    created: PassboltDateTimeType
    created_by: PassboltUserIdType
    deleted: bool
    modified: PassboltDateTimeType
    modified_by: PassboltUserIdType
    name: str
    groups_users: List[dict] = []


AllPassboltTupleTypes = Union[
    PassboltSecretTuple,
    PassboltPermissionTuple,
    PassboltResourceTuple,
    PassboltFolderTuple,
    PassboltGroupTuple,
    PassboltUserTuple,
    PassboltOpenPgpKeyTuple,
    PassboltAroTuple,
]


def tuple_constructor(
    _namedtuple: AllPassboltTupleTypes,
    renamed_fields: Union[None, dict] = None,
    filter_fields: bool = True,
    subconstructors: Union[None, dict] = None,
):
    def namedtuple_constructor(input: Union[Mapping, List[Mapping]]) -> Optional[List[AllPassboltTupleTypes]]:
        """Returns a namedtuple constructor function that can --
        1. Ingest dictionaries or list of dictionaries directly
        2. Renames field names from dict -> namedtuple
        3. Filters out dictionary keys that do not exist in namedtuple
        4. Can apply further constructors to subfields"""
        if input is None: return
        if input == []: return []

        # 1. ingest datatypes
        is_singleton = False
        if isinstance(input, dict):
            # if single, data is a singleton list
            input = [input]
            is_singleton = True
        elif isinstance(input, list):
            # if list, assert that all elements are dicts
            assert all(map(lambda element: type(element) == dict, input)), "All records must be dicts"
        else:
            raise ValueError(f"Data ingested by {_namedtuple} cannot be {type(input)}")

        # TODO: should the listcomps be made lazy?

        # 2. rename fields
        if renamed_fields:
            # make sure that all final fieldnames are present in the namedtuple
            assert not set(renamed_fields.values()).difference(_namedtuple._fields)
            input = [
                {(renamed_fields[k] if k in renamed_fields.keys() else k): v for k, v in datum.items()}
                for datum in input
            ]

        # 3. Filter extra fields not present in namedtuple definition
        if filter_fields:
            _ = input[0]
            input = [{k: v for k, v in element.items() if k in _namedtuple._fields} for element in input]

        # 4. [Composition] Apply constructors like this to individual fields
        if subconstructors:
            # todo: check if specified field is a string
            # if so, try to convert it to a dictionary. (example: resource type desctiption)
            input = [
                {
                    k: (subconstructors[k](v) if k in subconstructors.keys() else v)
                    for k, v in datum.items()
                    if k in _namedtuple._fields
                }
                for datum in input
            ]
        # handle singleton lists
        if is_singleton: return _namedtuple(**input[0])

        return [_namedtuple(**datum) for datum in input]

    return namedtuple_constructor
