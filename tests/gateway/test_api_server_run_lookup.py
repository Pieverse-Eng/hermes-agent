"""Authenticated run recovery through the production HTTP route table."""
from unittest.mock import patch

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from gateway.platforms.api_server_run_idempotency import RunIdempotencyStore
from tests.gateway.test_api_server_runs import _make_adapter
from tests.gateway.test_api_server_native_runs import RecordingAgent, settle


def app_for(adapter):
    app = web.Application()
    for method, path, handler in adapter._http_route_table():
        app.router.add_route(method, path, handler)
    return app


@pytest.mark.asyncio
async def test_lookup_recovers_native_identity_without_replaying_content(tmp_path):
    path = str(tmp_path / "runs.db")
    adapter = _make_adapter(api_key="owner-key")
    adapter._run_idempotency_store.close()
    adapter._run_idempotency_store = RunIdempotencyStore(path)
    agent = RecordingAgent()
    auth = {"Authorization": "Bearer owner-key"}
    with patch.object(adapter, "_create_agent", return_value=agent):
        async with TestClient(TestServer(app_for(adapter))) as client:
            response = await client.post("/v1/runs", headers={**auth, "Idempotency-Key": "platform-run"},
                                         json={"input": "private message"})
            assert response.status == 202
            native = (await response.json())["run_id"]
            await settle(adapter, native)
    adapter._run_idempotency_store.close()
    recovered = _make_adapter(api_key="owner-key")
    recovered._run_idempotency_store.close()
    recovered._run_idempotency_store = RunIdempotencyStore(path)
    try:
        async with TestClient(TestServer(app_for(recovered))) as client:
            response = await client.post("/v1/runs/lookup", headers=auth,
                                         json={"idempotency_key": "platform-run"})
            assert response.status == 200
            assert await response.json() == {"run_id": native, "status": "completed"}
            assert len(agent.histories) == 1
            assert (await client.post("/v1/runs/lookup", json={"idempotency_key": "platform-run"})).status == 401
            assert (await client.post("/v1/runs/lookup", headers=auth, json={"idempotency_key": "missing"})).status == 404
            assert (await client.post("/v1/runs/lookup", headers=auth, json={"idempotency_key": []})).status == 400
        with patch.object(recovered, "_expected_api_key", return_value="another-owner"):
            async with TestClient(TestServer(app_for(recovered))) as client:
                response = await client.post("/v1/runs/lookup", headers={"Authorization": "Bearer another-owner"},
                                             json={"idempotency_key": "platform-run"})
                assert response.status == 404
    finally:
        recovered._run_idempotency_store.close()
