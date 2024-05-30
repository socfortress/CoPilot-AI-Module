from fastapi import APIRouter
from loguru import logger
from schema.ai import WazuhRuleExclusionRequest, VelociraptorArtifactRecommendationRequest, VelociraptorArtifactRecommendationResponse
from schema.ai import WazuhRuleExclusionResponse
from services.wazuh_rule_exclusion import wazuh_assistant, artifact_analysis

ai_router = APIRouter()


@ai_router.post("/wazuh-rule-exclusion", response_model=WazuhRuleExclusionResponse)
async def post_wazuh_rule_exclusion(
    request: WazuhRuleExclusionRequest,
):
    logger.info("Received request to run wazuh rule exclusion.")

    return await wazuh_assistant(request)


@ai_router.post("/velociraptor-artifact-recommendation", response_model=VelociraptorArtifactRecommendationResponse)
async def post_velociraptor_artifact_recommendation(
    request: VelociraptorArtifactRecommendationRequest,
):
    logger.info("Received request to run velociraptor artifact recommendation.")

    return await artifact_analysis(request)
