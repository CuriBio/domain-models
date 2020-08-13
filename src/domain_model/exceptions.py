# -*- coding: utf-8 -*-
"""The domain models themselves."""

from typing import List
from typing import Tuple
from typing import Union


class NoPersistenceModelAttachedError(Exception):
    def __init__(self) -> None:
        super().__init__(
            "No persistence models are attached to this domain model. Persistence cannot occur."
        )


class NoSpecifiedTypeOfPersistenceModelAttachedError(Exception):
    def __init__(
        self,
        available_persistence_models: List[object],
        specified_instance_of: Union[Tuple[type], type],
    ) -> None:
        self._available_persistence_models = available_persistence_models
        self._specified_instance_of = specified_instance_of
        msg = f"The available persistence models were {available_persistence_models}. None available that matched the specified instance types: {specified_instance_of}"
        super().__init__(msg)


class DomainModelValidationError(Exception):
    def __init__(self, msg: str = None, append_text: str = None) -> None:
        msg = f"{msg} {append_text}"
        super().__init__(msg)


class ObjectNotDomainModelError(DomainModelValidationError):
    pass


class InvalidDomainModelSubclassError(DomainModelValidationError):
    pass


class ObjectIsNullError(DomainModelValidationError):
    pass
