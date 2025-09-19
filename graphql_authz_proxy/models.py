"""Models used throughout the app for users, groups, permissions, and policies."""

from enum import Enum
import json
from typing import Any, Optional, TypedDict

import yaml
from graphql import FieldNode
from pydantic import BaseModel

import jinja2


class _ConfigParser:
    @classmethod
    def parse_config(cls: type[BaseModel], config_path: str) -> BaseModel:
        """Parse a YAML config file and instantiate the model.

        Args:
            config_path (str): Path to YAML config file.

        Returns:
            BaseModel: Instantiated model from config.

        """
        try:
            with open(config_path) as f:
                config = yaml.safe_load(f)
            return cls(**config)
        except Exception as e:
            raise ValueError(f"Error parsing config file {config_path}.") from e
        
    @classmethod
    def parse_config_string(cls: type[BaseModel], config: str) -> BaseModel:
        """Parse a YAML config string and instantiate the model.

        Args:
            config (str): YAML config string.

        Returns:
            BaseModel: Instantiated model from config string.

        """
        try:
            config = yaml.safe_load(config)
            return cls(**config)
        except Exception as e:
            raise ValueError(f"Error parsing config string: {config}") from e


class User(BaseModel):

    """User model with username, email, and associated groups names."""

    username: str
    email: str
    groups: list[str]


class Users(_ConfigParser, BaseModel):

    """Users model containing a list of User objects."""

    users: list[User]
    _user_lookup_cache: dict[str, User] = {}
    _user_email_lookup_cache: dict[str, User] = {}

    def get_user(self, username: str) -> User | None:
        """Get a user by username.

        Args:
            username (str): Username to look up.

        Returns:
            User | None: User object if found, else None.

        """
        if username in self._user_lookup_cache:
            return self._user_lookup_cache[username]

        for user in self.users:
            if user.username == username.strip():
                self._user_lookup_cache[username] = user
                return user
        return None
    
    def get_user_by_email(self, email: str) -> User | None:
        """Get a user by email address.

        Args:
            email (str): Email to look up.

        Returns:
            User | None: User object if found, else None.

        """
        if email in self._user_email_lookup_cache:
            return self._user_email_lookup_cache[email]

        for user in self.users:
            if user.email == email.strip():
                self._user_email_lookup_cache[email] = user
                return user
        return None


class PolicyEffect(str, Enum):

    """Policy effect enum."""

    ALLOW = "allow"
    DENY = "deny"

# Recursive types used for type hinting complex-typed GraphQL variables
type Primitive = str | int | float | bool
type PrimitiveList = list[Primitive | PrimitiveDict | PrimitiveList]
type PrimitiveDict = dict[Primitive, Primitive | PrimitiveDict | PrimitiveList]
type Serializable = Primitive | PrimitiveDict | PrimitiveList


class ArgumentRule(BaseModel):

    """Argument rule model defining allowed values for a specific GraphQL field argument."""

    argument_name: str
    values: list[Serializable] | None

    def render_values(self, template_vars: dict[str, str]) -> list[str]:
        """Render the argument values as strings for logging or error messages.

        Returns:
            list[str]: List of argument values as strings.

        """
        if not self.values:
            return self.values

        rendered_values: list[Serializable] = []
        for value in self.values:
            serialized = json.dumps(value)
            environment = jinja2.Environment(autoescape=True)
            template = environment.from_string(serialized)
            rendered = template.render(template_vars)
            rendered_values.append(json.loads(rendered))

        self.values = rendered_values


class FieldRule(BaseModel):

    """Field rule model defining allowances or denials for a specific field."""

    field_name: str
    description: str | None = None
    arguments: list[ArgumentRule] | None = None
    field_rules: list["FieldRule"] | None = None

    def is_leaf(self) -> bool:
        """Check if this field rule is a leaf (no sub-field rules).

        Returns:
            bool: True if no sub-field rules, else False.

        """
        return not self.field_rules
    
    def render_argument_values(self, template_vars: dict[str, str]) -> None:
        """Render all argument rule values using provided template variables.

        Args:
            template_vars (dict[str, str]): Template variables for rendering.

        """
        if self.arguments:
            for arg_rule in self.arguments:
                arg_rule.render_values(template_vars)
        if self.field_rules:
            for sub_field_rule in self.field_rules:
                sub_field_rule.render_argument_values(template_vars)


class UserRules(BaseModel):

    """User rules model defining all field allowances and denials for a user."""

    query_field_allowances: list[FieldRule] | None = None
    mutation_field_allowances: list[FieldRule] | None = None
    query_field_denials: list[FieldRule] | None = None
    mutation_field_denials: list[FieldRule] | None = None

    def render_argument_values(self, template_vars: dict[str, str]) -> None:
        """Render all argument rule values using provided template variables.

        Args:
            template_vars (dict[str, str]): Template variables for rendering.

        """
        for field_rule_list in [
            self.query_field_allowances,
            self.mutation_field_allowances,
            self.query_field_denials,
            self.mutation_field_denials,
        ]:
            if field_rule_list:
                for field_rule in field_rule_list:
                    field_rule.render_argument_values(template_vars)


class QueryPolicy(BaseModel):

    """Query policy model defining effect and field rules."""

    effect: PolicyEffect
    fields: list[FieldRule] | None = None

    def model_post_init(self, _: None = None) -> None:
        """Post-init hook to set default deny-all if DENY effect and no fields."""
        if self.effect == PolicyEffect.DENY and self.fields is None:
            # Deny all fields if no fields specified
            self.fields = [
                FieldRule(field_name="*"),
            ]
    

class MutationPolicy(QueryPolicy):

    """Mutation policy model, inherits from QueryPolicy."""

    def model_post_init(self, _: None = None) -> None:
        """Post-init hook to set default deny-all if DENY effect and no fields."""
        if self.effect == PolicyEffect.DENY and self.fields is None:
            # Deny all fields if no fields specified
            self.fields = [
                FieldRule(field_name="*"),
            ]
    

class Permissions(BaseModel):

    """Permissions model defining policies for queries and mutations."""

    mutations: MutationPolicy | None = None
    queries: QueryPolicy | None = None

    def model_post_init(self, _: None) -> None:
        """Post-init hook to set default DENY for queries and mutations if not specified."""
        if not self.mutations:
            self.mutations = MutationPolicy(effect=PolicyEffect.DENY)
        if not self.queries:
            self.queries = QueryPolicy(effect=PolicyEffect.DENY)


class Group(BaseModel):

    """Group model with name and associated permissions."""

    name: str
    permissions: Permissions
    description: str | None = None


class Groups(_ConfigParser, BaseModel):

    """Groups model containing a list of Group objects."""

    groups: list[Group]
    idp_group_mapping: dict[str, str] | None = None

    _group_lookup_cache: dict[str, Group] = {}
    def get_group(self, group_name: str) -> Group | None:
        """Get a group by name.

        Args:
            group_name (str): Name of the group to look up.
            idp_group_mapping (dict[str, str] | None): Optional mapping of IdP group names to local group names.

        Returns:
            Group | None: Group object if found, else None.

        """
        if group_name in self._group_lookup_cache:
            return self._group_lookup_cache[group_name]

        for group in self.groups:
            if group.name == group_name.strip():
                self._group_lookup_cache[group_name] = group
                return group
            
        # If group not found, check IdP group mapping if configured
        if self.idp_group_mapping and group_name in self.idp_group_mapping:
            mapped_name = self.idp_group_mapping[group_name]
            for group in self.groups:
                if group.name == mapped_name.strip():
                    self._group_lookup_cache[group_name] = group
                    return group

        return None

# Recursive type representing an intermediate representation of parsed GraphQL document
type RenderedFields = dict[str, list[FieldNode] | RenderedFields]


class FieldNodeAttrs(TypedDict):

    """Attributes of a parsed GraphQL field node."""

    arguments: dict[str, Any] | None
    selection_set: Optional["FieldNodeDict"]


type FieldNodeDict = dict[str, FieldNodeAttrs]
