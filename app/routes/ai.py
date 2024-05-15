from app.schema.ai import WazuhRuleExclusionRequest
from app.schema.ai import WazuhRuleExclusionResponse
from fastapi import APIRouter
from loguru import logger
from services.wazuh_rule_exclusion import wazuh_assistant

ai_router = APIRouter()


@ai_router.post("/wazuh-rule-exclusion", response_model=WazuhRuleExclusionResponse)
async def post_test(
    request: WazuhRuleExclusionRequest,
):
    logger.info("Received request to rune wazuh rule exclusion.")

    return await wazuh_assistant(request)
