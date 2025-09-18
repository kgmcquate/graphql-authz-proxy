
from enum import Enum
from typing import Dict, List, Optional, TypedDict, Any
from graphql import FieldNode
from pydantic import BaseModel, field_validator, model_validator
import yaml
from functools import lru_cache

class _ConfigParser:
    @classmethod
    def parse_config(cls: type[BaseModel], config_path: str):
        try:
            with open(config_path, "r") as f:
                config = yaml.safe_load(f)
            return cls(**config)
        except Exception as e:
            raise ValueError(f"Error parsing config file {config_path}: {e}")

class User(BaseModel):
    username: str
    email: str
    groups: List[str]

class Users(_ConfigParser, BaseModel):
    users: List[User]

    # @lru_cache(maxsize=128)
    def get_user(self, username: str) -> Optional[User]:
        for user in self.users:
            if user.username == username.strip():
                return user
        return None
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        for user in self.users:
            if user.email == email.strip():
                return user
        return None


# class ParameterRestriction(BaseModel):
#     jsonpath: str
#     allowed_values: Optional[List[str | int | float | bool]] = None
#     forbidden_values: Optional[List[str | int | float | bool]] = None

#     @model_validator(mode='after')
#     def validate_values(self):
#         if self.allowed_values is not None and self.forbidden_values is not None:
#             raise ValueError("Cannot have both allowed_values and forbidden_values")
#         return self


class ArgumentRestriction(BaseModel):
    name: str
    allowed_values: Optional[List[str | int | float | bool]] = None
    forbidden_values: Optional[List[str | int | float | bool]] = None

    @model_validator(mode='after')
    def validate_values(self):
        if self.allowed_values is not None and self.forbidden_values is not None:
            raise ValueError("Cannot have both allowed_values and forbidden_values")
        return self
    
class FieldRestriction(BaseModel):
    name: str
    argument_restrictions: Optional[List[ArgumentRestriction]] = None
    field_restrictions: Optional[List['FieldRestriction']] = None

    def is_leaf(self):
        return not self.field_restrictions
    

class FieldAllowance(BaseModel):
    name: str
    argument_restriction: Optional[List[ArgumentRestriction]] = None
    field_allowances: Optional[List['FieldAllowance']] = None

    def is_leaf(self):
        return not self.field_allowances
    
class MutationPermissions(BaseModel):
    field_allowances: Optional[List[FieldAllowance]] = None
    field_restrictions: Optional[List[FieldRestriction]] = None

    @model_validator(mode='after')
    def validate_values(self):
        if self.field_allowances is not None and self.field_restrictions is not None:
            raise ValueError("Cannot have both field_allowances and field_restrictions")
        elif not self.field_allowances and not self.field_restrictions:
            raise ValueError("Must have either field_allowances or field_restrictions")
        return self

class QueryPermissions(BaseModel):
    field_allowances: Optional[List[FieldAllowance]] = None
    field_restrictions: Optional[List[FieldRestriction]] = None

    @model_validator(mode='after')
    def validate_values(self):
        if self.field_allowances is not None and self.field_restrictions is not None:
            raise ValueError("Cannot have both field_allowances and field_restrictions")
        elif not self.field_allowances and not self.field_restrictions:
            raise ValueError("Must have either field_allowances or field_restrictions")
        return self

class Permissions(BaseModel):
    mutations: Optional[MutationPermissions] = None
    queries: Optional[QueryPermissions] = None

class Group(BaseModel):
    name: str
    permissions: Permissions
    description: Optional[str] = None


class Groups(_ConfigParser, BaseModel):
    groups: List[Group]

    # @lru_cache(maxsize=128)
    def get_group(self, group_name: str) -> Optional[Group]:
        for group in self.groups:
            if group.name == group_name.strip():
                return group
        return None

type RenderedFields = Dict[str, List[FieldNode] | RenderedFields]

class FieldNodeAttrs(TypedDict):
    arguments: Optional[Dict[str, Any]]
    selection_set: Optional["FieldNodeDict"]
    
type FieldNodeDict = Dict[str, FieldNodeAttrs]
