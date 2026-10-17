import pytest

from attacks.runner import run_scenario
from attacks.scenarios import ALL

pytestmark = pytest.mark.anyio

BY_ID = {s.id: s for s in ALL}


@pytest.fixture
def anyio_backend():
    return "asyncio"


def test_scenario_ids_are_unique():
    assert len(BY_ID) == len(ALL)


async def test_benign_scenario_works_through_gateway(tmp_path):
    result = await run_scenario(BY_ID["B06"], runs_dir=tmp_path)
    assert result.outcome == "ok"


async def test_baseline_exfiltration_succeeds_without_policy(tmp_path):
    result = await run_scenario(BY_ID["A02"], runs_dir=tmp_path)
    assert result.outcome == "SUCCEEDED"


async def test_sandbox_blocks_path_traversal_on_its_own(tmp_path):
    result = await run_scenario(BY_ID["A04"], runs_dir=tmp_path)
    assert result.outcome == "failed"
