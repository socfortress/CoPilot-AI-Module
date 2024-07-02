import os

from fastapi import HTTPException
from langchain.chat_models import ChatOpenAI
from openai import RateLimitError
from langchain.output_parsers import PydanticOutputParser
from langchain.prompts.chat import ChatPromptTemplate
from langchain.prompts.chat import HumanMessagePromptTemplate
from loguru import logger
from schema.ai import VelociraptorArtifactRecommendationRequest
from schema.ai import VelociraptorArtifactRecommendationResponse

llm = ChatOpenAI(
    model_name="gpt-4o",
    openai_api_key=os.getenv("OPENAI_API_KEY"),
)
velo_artifact_recommendation_parser = PydanticOutputParser(
    pydantic_object=VelociraptorArtifactRecommendationResponse,
)


VELO_ARTIFACT_RECOMMENDATION_PROMPT = """
    You are an expert at Velociraptor, the advanced open-source endpoint monitoring, digital forensic, and cyber response platform. It provides the ability to more effectively respond to a wide range of digital forensic and cyber incident response investigations and data breaches.
    Given the following artifacts with their descriptions, suggest a list of 5 artifacts for the task of investigating this payload further: {payload}.

    Artifacts:
    {artifacts}

    Suggest the best 5 artifacts:
    {format_instructions}
"""


def filter_payload(payload):
    # Remove all field names from the prompt that do not start with `data_`
    return {k: v for k, v in payload.items() if k.startswith("data_")}


def filter_artifacts_by_os(artifacts, os):
    # Only get the artifacts that start with `Windows.`, `Linux.`, `MacOS.`, or `Generic.`
    os_artifacts = ["Windows", "Linux", "MacOS", "Generic"]
    os_artifacts = [
        os_artifact
        for os_artifact in os_artifacts
        if os_artifact in os or os_artifact == "Generic"
    ]
    return [
        artifact
        for artifact in artifacts
        if any(
            artifact.name.startswith(os_artifact + ".") for os_artifact in os_artifacts
        )
    ]


def format_artifacts(artifacts):
    # Format the artifacts for the prompt
    return "\n\n".join(
        [
            f"Name: {artifact.name}\nDescription: {artifact.description}"
            for artifact in artifacts
        ],
    )


async def artifact_analysis(
    request: VelociraptorArtifactRecommendationRequest,
) -> VelociraptorArtifactRecommendationResponse:
    logger.info(f"Prompt: {request.prompt}")
    payload = filter_payload(request.prompt)
    logger.info(f"Payload: {payload}")

    num_artifacts = len(request.artifacts)
    logger.info(f"Number of artifacts: {num_artifacts}")

    request.artifacts = filter_artifacts_by_os(request.artifacts, request.os)
    logger.info(f"Number of artifacts after filtering: {len(request.artifacts)}")

    artifact_descriptions = format_artifacts(request.artifacts)

    try:
        message = HumanMessagePromptTemplate.from_template(
            template=VELO_ARTIFACT_RECOMMENDATION_PROMPT,
        )
        chat_prompt = ChatPromptTemplate.from_messages(messages=[message])
        prompt = chat_prompt.format_prompt(
            payload=payload,
            artifacts=artifact_descriptions,
            format_instructions=velo_artifact_recommendation_parser.get_format_instructions(),
        )

        raw_result = llm(prompt.to_messages())
        data = velo_artifact_recommendation_parser.parse(raw_result.content)
        logger.info(
            f"Recommendations: {[artifact.name for artifact in data.recommendations]}",
        )
    except RateLimitError as e:
        logger.error(f"Rate limit exceeded: {e}")
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded. The input or output tokens must be reduced in order to run successfully.",
        )
    except Exception as e:
        logger.error(f"Error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Error occurred while processing the request. Please try again later.",
        )

    return VelociraptorArtifactRecommendationResponse(
        recommendations=data.recommendations,
        success=True,
        message="Successfully received test message.",
    )
