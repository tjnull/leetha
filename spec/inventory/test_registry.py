"""Phase A.3 — inventory importer registry."""

from leetha.inventory.registry import (
    register_importer,
    get_importer,
    get_all_importers,
    clear_registry,
)


def test_register_adds_to_registry():
    clear_registry()

    @register_importer("testfoo")
    class _Foo:
        pass

    assert get_importer("testfoo") is _Foo
    assert "testfoo" in get_all_importers()


def test_register_sets_name_on_class():
    clear_registry()

    @register_importer("nametest")
    class _N:
        pass

    assert _N._importer_name == "nametest"


def test_clear_registry_empties_it():
    clear_registry()

    @register_importer("ephemeral")
    class _E:
        pass

    assert get_importer("ephemeral") is _E
    clear_registry()
    assert get_importer("ephemeral") is None
    assert get_all_importers() == {}
