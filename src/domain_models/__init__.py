# -*- coding: utf-8 -*-
"""Models for basic business/domain logic."""
from .domain_models import DomainModel
from .domain_models import DomainModelWithUuid
from .domain_models import HashAttributesNotSpecifiedForClassError
from .domain_models import validate_domain_model
from .exceptions import InvalidDomainModelSubclassError
from .exceptions import NoPersistenceModelAttachedError
from .exceptions import NoSpecifiedTypeOfPersistenceModelAttachedError
from .exceptions import ObjectIsNullError
from .exceptions import ObjectNotDomainModelError

__all__ = [
    "DomainModel",
    "DomainModelWithUuid",
    "validate_domain_model",
    "ObjectNotDomainModelError",
    "ObjectIsNullError",
    "InvalidDomainModelSubclassError",
    "NoPersistenceModelAttachedError",
    "NoSpecifiedTypeOfPersistenceModelAttachedError",
    "HashAttributesNotSpecifiedForClassError",
]
