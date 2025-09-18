
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


class PolicyEffect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class ArgumentRule(BaseModel):
    argument_name: str
    values: Optional[List[str | int | float | bool]]
    

class FieldRule(BaseModel):
    field_name: str
    description: Optional[str] = None
    arguments: Optional[List[ArgumentRule]] = None
    field_rules: Optional[List['FieldRule']] = None

    def is_leaf(self):
        return not self.field_rules


class QueryPolicy(BaseModel):
    effect: PolicyEffect
    fields: Optional[List[FieldRule]] = None

    def model_post_init(self, __context__=None) -> None:
        if self.effect == PolicyEffect.DENY:
            if self.fields is None:
                # Deny all fields if no fields specified
                self.fields = [
                    FieldRule(field_name="*")
                ]
    

class MutationPolicy(QueryPolicy):
    def model_post_init(self, __context__=None) -> None:
        if self.effect == PolicyEffect.DENY:
            if self.fields is None:
                # Deny all fields if no fields specified
                self.fields = [
                    FieldRule(field_name="*")
                ]
    

class Permissions(BaseModel):
    mutations: Optional[MutationPolicy] = None
    queries: Optional[QueryPolicy] = None

    def model_post_init(self, __context__=None) -> None:
        if not self.mutations:
            self.mutations = MutationPolicy(effect=PolicyEffect.DENY)
        if not self.queries:
            self.queries = QueryPolicy(effect=PolicyEffect.DENY)


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
