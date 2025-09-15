
from enum import Enum
from typing import List, Optional
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

class UserConfig(BaseModel):
    username: str
    email: str
    groups: List[str]
    permissions: Optional[List[str]] = None

class UsersConfig(_ConfigParser, BaseModel):
    users: List[UserConfig]

    # @lru_cache(maxsize=128)
    def get_user(self, username: str) -> Optional[UserConfig]:
        for user in self.users:
            if user.username == username.strip():
                return user
        return None
    
    def get_user_by_email(self, email: str) -> Optional[UserConfig]:
        for user in self.users:
            if user.email == email.strip():
                return user
        return None


class GraphQLOperationType(str, Enum):
    QUERY = "query"
    MUTATION = "mutation"
    # SUBSCRIPTION = "subscription"


class ParameterRestriction(BaseModel):
    jsonpath: str
    allowed_values: Optional[List[str | int | float | bool]] = None
    forbidden_values: Optional[List[str | int | float | bool]] = None

    @model_validator(mode='after')
    def validate_values(self):
        if self.allowed_values is not None and self.forbidden_values is not None:
            raise ValueError("Cannot have both allowed_values and forbidden_values")
        return self


class Rule(BaseModel):
    operation_name: str
    description: Optional[str] = None
    parameter_restrictions: Optional[List[ParameterRestriction]] = None


class PermissionConfig(BaseModel):
    mutations: List[Rule]
    queries: List[Rule]

class GroupConfig(BaseModel):
    name: str
    description: str
    permissions: PermissionConfig


class GroupsConfig(_ConfigParser, BaseModel):
    groups: List[GroupConfig]

    # @lru_cache(maxsize=128)
    def get_group(self, group_name: str) -> Optional[GroupConfig]:
        for group in self.groups:
            if group.name == group_name.strip():
                return group
        return None

