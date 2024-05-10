from fastapi import APIRouter
from fastapi import Depends
from loguru import logger
from schema.event_shipper import EventShipperPayload
from schema.test import TestRequest
from schema.test import TestResponse
from services.event_shipper import event_shipper
from services.license import validate_license
from services.wazuh_rule_exclusion import wazuh_assistant

test_router = APIRouter()


@test_router.post("/test", response_model=TestResponse)
async def post_test(
    request: TestRequest,
    license_key: str,
    # feature_name: str = Depends(validate_license),
):
    logger.info("Test Route Called")
    # await wazuh_rule_exclusion(request)
    # await using_tools_and_agent(request)
    # await wazuh_assistant(request)

    return await wazuh_assistant(request)
