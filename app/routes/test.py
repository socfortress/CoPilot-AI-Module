from fastapi import APIRouter
from loguru import logger
from schema.test import TestRequest
from schema.test import TestResponse
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
