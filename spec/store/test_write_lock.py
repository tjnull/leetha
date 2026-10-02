"""The legacy and repository stores must coordinate writes to one SQLite file."""

import asyncio

import pytest

from leetha.store.write_lock import write_lock_for


@pytest.mark.asyncio
async def test_locks_for_same_database_serialize_writers(tmp_path):
    first = write_lock_for(tmp_path / "inventory.db")
    second = write_lock_for(tmp_path / "inventory.db")
    entered = asyncio.Event()
    released = asyncio.Event()

    async def contender():
        async with second:
            entered.set()

    async with first:
        task = asyncio.create_task(contender())
        await asyncio.sleep(0.03)
        assert not entered.is_set()
        released.set()
    await asyncio.wait_for(task, timeout=1)
    assert released.is_set() and entered.is_set()
