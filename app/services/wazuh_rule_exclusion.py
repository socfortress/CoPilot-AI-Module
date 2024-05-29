import json
import os
import re

from langchain.chat_models import ChatOpenAI
from langchain.output_parsers import PydanticOutputParser
from langchain_community.document_loaders import TextLoader
from langchain.prompts.chat import ChatPromptTemplate
from langchain.vectorstores import FAISS
from langchain.embeddings.openai import OpenAIEmbeddings
from langchain.prompts.chat import HumanMessagePromptTemplate
from langchain_community.document_loaders import UnstructuredURLLoader
from langchain_community.document_loaders import UnstructuredXMLLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.tools import ShellTool
from langchain_core.exceptions import OutputParserException
from loguru import logger
from pydantic import BaseModel
from pydantic import Field
from pydantic import validator
from schema.ai import WazuhRuleExclusionRequest, VelociraptorArtifactRecommendationRequest
from schema.ai import WazuhRuleExclusionResponse


class Country(BaseModel):
    capital: str = Field(description="The capital of the country.")
    name: str = Field(description="The name of the country.")


class WazuhExclusionRuleData(BaseModel):
    wazuh_rule: str = Field(
        ...,
        description="The XML formatted Wazuh rule created for exclusion purposes.",
    )
    explanation: str = Field(
        ...,
        description="A detailed explanation of the purpose and function of the new rule.",
    )

    @validator("wazuh_rule", "explanation", pre=True)
    def cleanup(cls, value):
        # Add your cleanup logic here
        cleaned_value = value.strip()  # For example, remove leading/trailing whitespace
        return cleaned_value

class VelociraptorArtifactRecommendation(BaseModel):
    name: str = Field(
        ...,
        description="The name of the artifact."
    )
    description: str = Field(
        ...,
        description="A description of the artifact."
    )
    explanation: str = Field(
        ...,
        description="A detailed explanation of the purpose and why the artifact was selected."
    )


llm = ChatOpenAI(
    model_name="gpt-4o",
    openai_api_key=os.getenv("OPENAI_API_KEY"),
)
shell_tool = ShellTool(handle_parsing_errors=True)
parser = PydanticOutputParser(pydantic_object=WazuhExclusionRuleData)
velo_artifact_recommendation_parser = PydanticOutputParser(pydantic_object=VelociraptorArtifactRecommendation)

PROMPT_EXAMPLE = """
    Provide information about {country}.
    {format_instructions}
    """

windows_field_names_to_prefer = [
    "data_win_eventdata_user",
    "data_win_eventdata_originalFileName",
    "data_win_eventdata_image",
    "data_win_eventdata_parentCommandLine",
    "data_win_eventdata_targetFilename",
    "data_win_eventdata_targetObject",
]


NEW_PROMPT_EXCLUSION_RULE = """
    You are an expert at creating Wazuh Rules.
    I want you to take this payload: {payload} and create a new Wazuh rule based on the values from the payload. The level of the new rule should be set to 1.
    You will pick out what keys and values should be used from the received payload to create a new Wazuh rule using PCRE2 syntax which can be found here: {pcre2_docs}.

    You will pick out what keys and values should be used from the received payload to create a new Wazuh rule using PCRE2 syntax and to set that level to 1. The data key field names that are applicable for use must start with `data_`. Always read the `rule_id` and use that value in the newly created rule as the `<if_sid>`.
    The created Wazuh rule should not have the `data_` in the `<field name=`. For example, the field name of `data_system_Task` that is in the JSON, would be `system_Task` in the created Wazuh exclusion rule.
    Requirements:
        1. Replace any `_` within the `<field name=` with a `.`.
        2. Do not use `\` to escape a `.` in the created Wazuh rule.
        3. Always use `(?i)` to enable case insensitive matching in the created Wazuh rule.
        4. When it makes since use the `^` to match the beginning of the string and the `$` to match the end of the string for the
            contents of the `<field name=`.
        5. Ensure that the opening rule tag includes both the rule ID and level within the same tag, following this syntax: `<rule id="replace_me" level="1">`. This format must be used to define the rule's ID and its severity level correctly within the rule definition.

    Make sure to include at least 3 `<field name=` in the created Wazuh rule. If you do not think a rule requires at least 3, still create the rule but state in your explanation that you recommend the SOC analyst to add more fields.
    Wazuh Rule Syntax documentation: {rule_syntax_docs}

    Example rules in PCRE2 syntax: {example_rules}. I want you to favor the field names: {windows_field_names_to_prefer} if these are applicable. If you find that the field names are not applicable, then you can use other field names.
    {format_instructions}
"""


VELO_PROMPT_TEST = """
    You are an expert at Incident Response using the tool Velociraptor.
    I want you to select the recemmonded artifact you want me to run based on this Wazuh Alert: {payload}.

    Here are the artifacts to select from: {artifacts}
    """


async def load_xml_data(file_path: str):
    xml_loader = UnstructuredXMLLoader(file_path)
    return xml_loader.load()


async def load_url_data(urls: list):
    url_loader = UnstructuredURLLoader(urls=urls)
    return url_loader.load()


async def format_chat_prompt(
    prompt: WazuhRuleExclusionRequest,
    parser,
    example_rules,
    pcre2_docs,
    rule_syntax_docs,
    windows_field_names_to_prefer,
):
    message = HumanMessagePromptTemplate.from_template(
        template=NEW_PROMPT_EXCLUSION_RULE,
    )
    chat_prompt = ChatPromptTemplate.from_messages(messages=[message])
    return chat_prompt.format_prompt(
        payload=prompt.prompt,
        format_instructions=parser.get_format_instructions(),
        example_rules=example_rules,
        pcre2_docs=pcre2_docs,
        rule_syntax_docs=rule_syntax_docs,
        windows_field_names_to_prefer=windows_field_names_to_prefer,
    )


def extract_rule_xml_from_output(raw_output: str) -> str:
    """
    Extracts XML content from the given raw output string.

    Args:
    raw_output (str): The raw output containing the XML data.

    Returns:
    str: The extracted XML content or an empty string if no XML is found.
    """
    # Regular expression pattern to capture XML content between specific markers
    pattern = r"```xml\n(.*?)\n```"
    match = re.search(pattern, raw_output, re.DOTALL)
    if match:
        return match.group(1)  # Return the matched XML content
    return ""  # Return an empty string if no match is found


def extract_json_from_raw_output(raw_output: str) -> tuple:
    """
    Extracts the explanation and wazuh_rule from the given raw output string.

    Args:
    raw_output (str): The raw output containing the explanation and wazuh_rule.

    Returns:
    tuple: The extracted explanation and wazuh_rule or empty strings if not found.
    """
    # Regular expression pattern to capture the JSON output
    pattern = r"```json\n(.*?)\n```"
    match = re.search(pattern, raw_output, re.DOTALL)
    if match:
        json_output = match.group(1)  # Extract the JSON output
        data = json.loads(json_output)  # Parse the JSON output
        explanation = data.get("explanation", "")  # Extract the explanation
        wazuh_rule = data.get("wazuh_rule", "")  # Extract the wazuh_rule
        wazuh_rule = re.sub(r'(?<=<rule id=")[^"]*', "replace_me", wazuh_rule)
        wazuh_rule = re.sub(
            r"(</.*?>)",
            r"\1\n",
            wazuh_rule,
        )  # Add a newline after every closing </>
        return explanation, wazuh_rule
    return (
        "Unfortunately, I couldn't extract the explanation and from the output. Please check the output manually.",
        extract_rule_xml_from_output(raw_output),
    )


# ! WILL RETRY WHOLE PROCESS IF ERROR ! #
async def wazuh_assistant(
    prompt: WazuhRuleExclusionRequest,
    max_retries: int = 3,
) -> WazuhRuleExclusionResponse:
    for _ in range(max_retries):
        try:
            script_dir = os.path.dirname(os.path.realpath(__file__))
            filename = os.path.join(script_dir, "wazuh_rules_example_data.xml")
            example_rules = await load_xml_data(filename)
            pcre2_docs = await load_url_data(
                [
                    "https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/regex.html",
                ],
            )
            rule_syntax_docs = await load_url_data(
                [
                    "https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html",
                ],
            )
            chat_prompt_with_values = await format_chat_prompt(
                prompt,
                parser,
                example_rules,
                pcre2_docs,
                rule_syntax_docs,
                windows_field_names_to_prefer,
            )
            raw_result = llm(chat_prompt_with_values.to_messages())
            data = parser.parse(raw_result.content)
            logger.info(f"Rule: {data.wazuh_rule}, Explanation: {data.explanation}")
            return WazuhRuleExclusionResponse(
                wazuh_rule=data.wazuh_rule,
                explanation=data.explanation,
                message="Successfully received test message.",
                success=True,
            )
        except OutputParserException as e:
            explanation_output, wazuh_rule = extract_json_from_raw_output(
                raw_result.content,
            )
            logger.error(f"Attempt failed with OutputParserException: {e}")
            return WazuhRuleExclusionResponse(
                wazuh_rule=wazuh_rule,
                explanation=explanation_output,
                message="Failed to parse output, returning raw XML as JSON.",
                success=True,
            )
        except Exception as e:
            logger.error(f"Attempt failed with unexpected exception: {e}")
            break
    return WazuhRuleExclusionResponse(
        wazuh_rule=None,
        explanation=None,
        message="Failed to receive test message after multiple attempts.",
        success=False,
    )


# ! VELOCIRAPTOR ANALYSIS ! #

VELO_ARTIFACT_RECOMMENDATION_PROMPT = """
    You are an expert at Velociraptor. The advanced open-source endpoint monitoring, digital forensic and cyber response platform. It provides you with the ability to more effectively respond to a wide range of digital forensic and cyber incident response investigations and data breaches.
    Given the following artifacts with their descriptions, suggest the best list of artifacts for the task of investigating this payload further {payload}.

    Artifacts:
    {artifacts}

    Suggest the best artifact:
    {format_instructions}
"""

async def artifact_analysis(
    request: VelociraptorArtifactRecommendationRequest,
) -> WazuhRuleExclusionResponse:
    # ! I should host an API that returns the artifacts data ...actually no ill call the velo API !
    payload = {
        "alert": "Malware Detected",
    }

    # Get the number of items in the artifacts list
    num_artifacts = len(request.artifacts)
    logger.info(f"Number of artifacts: {num_artifacts}")



    # Get the first 100 artifacts
    # Only get the artifacts that start with `Windows.`, `Linux.`, `MacOS.`, or `Generic.`.
    request.artifacts = [artifact for artifact in request.artifacts if artifact.name.startswith(("Windows."))]
    logger.info(f"Number of artifacts after filtering: {len(request.artifacts)}")

    # Format the artifacts for the prompt
    artifact_descriptions = "\n\n".join([f"Name: {artifact.name}\nDescription: {artifact.description}" for artifact in request.artifacts])
    #artifact_descriptions = "\n\n".join([f"Name: {artifact.name}\nDescription: {artifact.description}" for artifact in first_100_artifacts])

    message = HumanMessagePromptTemplate.from_template(
        template=VELO_ARTIFACT_RECOMMENDATION_PROMPT,
    )
    chat_prompt = ChatPromptTemplate.from_messages(messages=[message])
    prompt = chat_prompt.format_prompt(
        payload=payload,
        artifacts=artifact_descriptions,
        format_instructions=velo_artifact_recommendation_parser.get_format_instructions(),
    )

    # Run it
    raw_result = llm(prompt.to_messages())

    # Parse the output
    data = velo_artifact_recommendation_parser.parse(raw_result.content)
    logger.info(f"Artifact: {data.name}, Explanation: {data.explanation}")





    return None
