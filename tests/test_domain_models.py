# -*- coding: utf-8 -*-
from typing import Optional
from uuid import UUID
from uuid import uuid4

from domain_models import DomainModel
from domain_models import DomainModelWithUuid
from domain_models import HashAttributesNotSpecifiedForClassError
from domain_models import InvalidDomainModelSubclassError
from domain_models import NoPersistenceModelAttachedError
from domain_models import NoSpecifiedTypeOfPersistenceModelAttachedError
from domain_models import ObjectIsNullError
from domain_models import ObjectNotDomainModelError
from domain_models import validate_domain_model
from immutable_data_validation.errors import ValidationCollectionEmptyValueError
import pytest


class DummyPersister:
    # pylint: disable=too-few-public-methods
    def persist(self, obj_to_persist):
        pass


class SubclassedDomainModel1(DomainModel):
    _hash_attribute_names = ("uuid", "other_int")

    def __init__(
        self, uuid: Optional[UUID] = None, other_int: Optional[int] = None
    ) -> None:
        super().__init__()
        self.uuid = uuid
        self.other_int = other_int


class SubclassedDomainModel2(DomainModel):
    pass


class DomainModelWithNumber(DomainModel):
    _hash_attribute_names = ("number",)

    def __init__(self) -> None:
        super().__init__()
        self.number = 0


def test_DomainModel_persist_calls_validate(mocker):
    m = DomainModel()
    m.add_persistence_model(DummyPersister())
    mocked_validate = mocker.patch.object(m, "validate")
    m.persist()
    assert mocked_validate.call_count == 1


def test_DomainModel_persist_calls_autopopulate(mocker):
    m = DomainModel()
    m.add_persistence_model(DummyPersister())
    mocked_autopopulate = mocker.patch.object(m, "autopopulate")
    m.persist()
    assert mocked_autopopulate.call_count == 1


def test_DomainModel_persist_calls_persisters(mocker):
    persister_1 = DummyPersister()
    persister_2 = DummyPersister()

    m = DomainModel()
    m.add_persistence_model(persister_1)
    m.add_persistence_model(persister_2)
    mocked_persist_1 = mocker.patch.object(persister_1, "persist")
    mocked_persist_2 = mocker.patch.object(persister_2, "persist")
    m.persist()

    mocked_persist_1.assert_called_once_with(m)
    mocked_persist_2.assert_called_once_with(m)


def test_validate_domain_model_calls_validate_and_autopopulate_of_that_model(mocker):
    m = DomainModel()
    spied_validate = mocker.spy(m, "validate")
    spied_autopopulate = mocker.spy(m, "autopopulate")
    validate_domain_model(m)
    assert spied_validate.call_count == 1
    assert spied_autopopulate.call_count == 1


def test_validate_domain_model_does_not_autopopulated_if_disabled(mocker):
    m = DomainModel()
    spied_validate = mocker.spy(m, "validate")
    spied_autopopulate = mocker.spy(m, "autopopulate")
    validate_domain_model(m, autopopulate=False)
    assert spied_validate.call_count == 1
    assert spied_autopopulate.call_count == 0


def test_validate_domain_model_does_not_autopopulated_if_disabled_and_validate_is_disabled(
    mocker,
):
    m = DomainModel()
    spied_validate = mocker.spy(m, "validate")
    spied_autopopulate = mocker.spy(m, "autopopulate")
    validate_domain_model(m, autopopulate=False, validate=False)
    assert spied_validate.call_count == 0
    assert spied_autopopulate.call_count == 0


def test_validate_domain_model_raises_error_if_not_domain_model():
    with pytest.raises(ObjectNotDomainModelError) as e:
        validate_domain_model(27, extra_error_msg="blah19")
    assert "blah19" in str(e)


def test_validate_domain_model_raises_error_if_None():
    with pytest.raises(ObjectIsNullError) as e:
        validate_domain_model(None, extra_error_msg="blah32")
    assert "blah32" in str(e)


def test_validate_domain_model_does_not_raise_error_if_None_and_allowed():
    # would raise error if failed
    validate_domain_model(None, allow_null=True)


def test_validate_domain_model_raises_error_if_not_correct_single_type():
    m = DomainModel()
    with pytest.raises(InvalidDomainModelSubclassError) as e:
        validate_domain_model(
            m, instance_of=SubclassedDomainModel1, extra_error_msg="wakka7"
        )
    assert "wakka7" in str(e)


def test_validate_domain_model_raises_error_if_not_correct_tuple_of_types():
    m = DomainModel()
    with pytest.raises(InvalidDomainModelSubclassError) as e:
        validate_domain_model(
            m,
            instance_of=(SubclassedDomainModel1, SubclassedDomainModel2),
            extra_error_msg="wakka98",
        )
    assert "wakka98" in str(e)


def test_validate_domain_model_does_not_raise_error_if_correct_in_tuple_of_types():
    m = SubclassedDomainModel2()
    validate_domain_model(
        m, instance_of=(SubclassedDomainModel1, SubclassedDomainModel2)
    )


def test_validate_domain_model__does_not_validate_model_if_set(mocker):
    m = DomainModel()
    mocked_validate = mocker.spy(m, "validate")
    validate_domain_model(m, validate=False)
    assert mocked_validate.call_count == 0


def test_validate_domain_model__still_autopopulates_even_if_not_validating(mocker):
    m = DomainModel()
    mocked_autopopulate = mocker.spy(m, "autopopulate")
    validate_domain_model(m, validate=False)
    assert mocked_autopopulate.call_count == 1


def test_DomainModel_autopopulate_populates_uuid_if_present():
    m = SubclassedDomainModel1()
    m.autopopulate()
    assert m.uuid is not None


def test_DomainModel_autopopulate_does_not_overwrite_existing_uuid():
    m = SubclassedDomainModel1(uuid="bob")
    m.autopopulate()
    assert m.uuid == "bob"


def test_DomainModel_validate_calls_autopopulate_by_default(mocker):
    m = DomainModel()
    mocked_autopopulate = mocker.spy(m, "autopopulate")
    m.validate()
    assert mocked_autopopulate.call_count == 1


def test_DomainModel_validate_calls_validate_internals(mocker):
    m = DomainModel()
    spied_validate_internals = mocker.spy(m, "validate_internals")
    m.validate()
    assert spied_validate_internals.call_count == 1


def test_DomainModel_validate_internals_calls_autopopulate_by_default(mocker):
    m = DomainModel()
    spied_autopopulate = mocker.spy(m, "autopopulate")
    m.validate_internals()
    assert spied_autopopulate.call_count == 1


def test_DomainModel_validate_hash_components_calls_autopopulate_by_default(mocker):
    m = DomainModel()
    spied_autopopulate = mocker.spy(m, "autopopulate")
    m.validate_hash_components()
    assert spied_autopopulate.call_count == 1


def test_DomainModel__hash__calls_validate_hash_components(mocker):
    m = DomainModelWithNumber()
    spied_validate_hash = mocker.spy(m, "validate_hash_components")
    hash(m)
    assert spied_validate_hash.call_count == 1


def test_DomainModel__hash__uses_hash_attribute_names():
    m = SubclassedDomainModel1()
    m.uuid = uuid4()
    m.other_int = 22
    expected_hash = hash((m.uuid, 22))
    actual_hash = hash(m)
    assert actual_hash == expected_hash


def test_DomainModel__hash__raises_error_if_attributes_not_specified():
    m = DomainModel()
    with pytest.raises(HashAttributesNotSpecifiedForClassError) as e:
        hash(m)
    assert "DomainModel" in str(e)


def test_DomainModel_persist_raises_error_if_no_persisters_added():
    m = DomainModel()
    with pytest.raises(NoPersistenceModelAttachedError):
        m.persist()


def test_DomainModel_get_persistence_model__returns_single_persister_if_one_present():
    m = DomainModel()
    p = DummyPersister()
    m.add_persistence_model(p)

    actual = m.get_persistence_model(object)
    assert actual == p


def test_DomainModel_get_persistence_model__raises_error_if_persistence_model_type_not_present():
    m = DomainModel()
    p = DummyPersister()
    m.add_persistence_model(p)

    with pytest.raises(NoSpecifiedTypeOfPersistenceModelAttachedError):
        m.get_persistence_model(DomainModel)


def test_DomainModel__persist__calls_persist_additional_models(mocker):
    m = DomainModel()
    m.add_persistence_model(DummyPersister())
    mocked_func = mocker.patch.object(m, "_persist_additional_models")
    m.persist()
    assert mocked_func.call_count == 1


def test_DomainModelWithUuid__uuid_can_be_set_during_init():
    m = DomainModelWithUuid(uuid=uuid4())
    assert m.uuid is not None
    assert isinstance(m.uuid, UUID) is True


def test_DomainModelWithUuid__autopopulates_uuid():
    m = DomainModelWithUuid()
    m.autopopulate()
    assert m.uuid is not None
    assert isinstance(m.uuid, UUID) is True


def test_DomainModelWithUuid__validate_hash_components_fails_if_uuid_is_not_set_and_autopopulate_is_false():
    m = DomainModelWithUuid()
    with pytest.raises(ValidationCollectionEmptyValueError) as e:
        m.validate_hash_components(autopopulate=False)
    assert "uuid" in str(e)


def test_DomainModelWithUuid__validate_hash_components__does_not_raise_error_because_autopopulate_true_by_default():
    m = DomainModelWithUuid()
    assert m.uuid is None
    m.validate_hash_components()
    assert m.uuid is not None
