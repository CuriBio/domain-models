# -*- coding: utf-8 -*-
"""The domain models themselves."""
from typing import Any
from typing import List
from typing import Optional
from typing import Tuple
from typing import Union
from uuid import UUID
from uuid import uuid4

from immutable_data_validation import validate_uuid

from .exceptions import InvalidDomainModelSubclassError
from .exceptions import NoPersistenceModelAttachedError
from .exceptions import NoSpecifiedTypeOfPersistenceModelAttachedError
from .exceptions import ObjectIsNullError
from .exceptions import ObjectNotDomainModelError


class DomainModel:
    """Base class for all domain models."""

    _hash_attribute_names: Tuple[str, ...] = tuple()

    def __init__(self) -> None:
        self._persistence_models: List[Any] = list()

    def __hash__(self) -> int:
        self.validate_hash_components()
        attr_name_list = self._hash_attribute_names
        if len(attr_name_list) == 0:
            raise HashAttributesNotSpecifiedForClassError(self)
        list_of_hash_components: List[Any] = list()
        for this_attr_name in attr_name_list:
            list_of_hash_components.append(getattr(self, this_attr_name))
        return hash(tuple(list_of_hash_components))

    def validate_hash_components(self, autopopulate: bool = True) -> None:
        """Validate the components that make up the hash."""
        if autopopulate:
            self.autopopulate()

    def validate_internals(self, autopopulate: bool = True) -> None:
        """Validate basic internally stored information.

        A full validation is required to persist, but there may be cases
        where just some information stored internally is needed to
        display in a read-only manner. validate_internals only validates
        items contained within this object and closely nearby---not
        everything from other databases that may need to be loaded and
        checked for validation during full validation before persisting
        """
        self.validate_hash_components(autopopulate=autopopulate)

    def validate(self, autopopulate: bool = True) -> None:
        self.validate_internals(autopopulate=autopopulate)

    def autopopulate(self) -> None:
        """Autopopulate model attributes."""
        if hasattr(
            self,
            "uuid",  # pylint: disable=access-member-before-definition
            # Eli (11/5/19) not sure why pylint is upset about this since it is testing for the presence of attribute...
        ):
            if (
                self.uuid  # pylint: disable=attribute-defined-outside-init,access-member-before-definition
                is None
            ):
                self.uuid: Optional[  # pylint: disable=attribute-defined-outside-init
                    UUID
                ] = uuid4()

    def add_persistence_model(self, persistence_model: object) -> None:
        self._persistence_models.append(persistence_model)

    def get_persistence_model(self, instance_of: Union[Tuple[type], type]) -> object:
        for this_persistence_model in self._persistence_models:
            if isinstance(this_persistence_model, instance_of):
                return this_persistence_model
        raise NoSpecifiedTypeOfPersistenceModelAttachedError(
            self._persistence_models, instance_of
        )

    def _persist_additional_models(self) -> None:
        pass

    def persist(self) -> None:
        self.validate()
        if len(self._persistence_models) == 0:
            raise NoPersistenceModelAttachedError()
        self._persist_additional_models()
        for this_persistence_model in self._persistence_models:
            this_persistence_model.persist(self)


def validate_domain_model(
    value: Any,
    allow_null: bool = False,
    autopopulate: bool = True,
    extra_error_msg: str = None,
    instance_of: Union[None, Tuple[type]] = None,
    validate: bool = True,
) -> None:
    """Validate a domain model as an attribute of another domain model.

    The style mimics the immutable_data_validation package.
    """
    if value is None:
        if allow_null:
            return
        raise ObjectIsNullError(append_text=extra_error_msg)
    if not isinstance(value, DomainModel):
        raise ObjectNotDomainModelError(append_text=extra_error_msg)

    if instance_of is not None:
        if not isinstance(value, instance_of):
            raise InvalidDomainModelSubclassError(append_text=extra_error_msg)
    if validate:
        value.validate(autopopulate=autopopulate)
        return
    if autopopulate:
        value.autopopulate()


class DomainModelWithUuid(DomainModel):
    """Covers common case where the hash is just a UUID."""

    _hash_attribute_names: Tuple[str, ...] = ("uuid",)

    def __init__(self, uuid: Optional[UUID] = None):
        super().__init__()
        self.uuid = uuid

    def validate_hash_components(self, autopopulate: bool = True) -> None:
        """Validate the components that make up the hash."""
        super().validate_hash_components(autopopulate=autopopulate)
        self.uuid = validate_uuid(self.uuid, extra_error_msg="uuid")


class HashAttributesNotSpecifiedForClassError(Exception):
    def __init__(self, model_instance: DomainModel) -> None:
        msg = f"The class '{type(model_instance)}' does not have hash attributes specified. These need to be added to the class definition."
        super().__init__(msg)
