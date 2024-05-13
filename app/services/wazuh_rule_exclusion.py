import json
import re

from datamgmt.configmanager import get_openai_from_config
from langchain.chat_models import ChatOpenAI
from langchain.output_parsers import PydanticOutputParser
from langchain.prompts.chat import ChatPromptTemplate
from langchain.prompts.chat import HumanMessagePromptTemplate
from langchain_community.document_loaders import UnstructuredURLLoader
from langchain_community.document_loaders import UnstructuredXMLLoader
from langchain_community.tools import ShellTool
from langchain_core.exceptions import OutputParserException
from loguru import logger
from pydantic import BaseModel
from pydantic import Field
from pydantic import validator
from schema.test import TestRequest
from schema.test import TestResponse


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


llm = ChatOpenAI(
    model_name="gpt-4-turbo",
    openai_api_key=get_openai_from_config().OPENAI_API_KEY,
)
shell_tool = ShellTool(handle_parsing_errors=True)
parser = PydanticOutputParser(pydantic_object=WazuhExclusionRuleData)

PROMPT_EXAMPLE = """
    Provide information about {country}.
    {format_instructions}
    """

PROMPT_EXCLUSION_RULE = """
    You are expert in creating regex matches using PCRE2 syntax. You understands how to receive JSON data which pertains to an event
    ingested into a SIEM stack, using Elasticsearch as the backend, and creates a Wazuh rule and sets the level to 1, based on the values
    from the received {payload}. You will pick out what keys and values should be used from the received payload to create a new Wazuh
    rule using PCRE2 syntax and to set that level to 1. The data key field names that are applicable for use must start
    with `data_`. Always read the `rule_id` and use that value in the newly created rule as the `<if_sid>`.
    The created Wazuh rule should not have the `data_` in the `<field name=`. For example, the field name of `data_system_Task`
    that is in the JSON, would be `system_Task` in the created Wazuh exclusion rule.
    Also replace any `_` within the `<field name=` with a `.`.
    A file path such as `C:\\Windows\\System32\\notepad.exe` should be `C:\\\\Windows\\\\System32\\\\notepad\.exe`.
    A `/` should be replaced with `\/` in the created Wazuh rule.
    A `\\` should be replaced with `\\\\` in the created Wazuh rule.

    Determine field names that have values that are too dynamic and exclude those from the created exclusion rule.
    For example, any field names with processID, time, level, etc. contain values that would not be good for an exclusion
    rule because they will likely not always be unique. You need to focus on using field names whoms values will likely be static.
    Do not include `agent_name`, `agent_labels_customer` in your created Wazuh rule. Only respond with the formatted instructions.
    Here are example rules: {example_rules}.
    Wazuh documentation examples: {url_docs}
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


# NEW_PROMPT_EXCLUSION_RULE = """
#     You are an expert at creating Wazuh Rules.
#     I want you to take this payload: {payload} and create a new Wazuh rule based on the values from the payload. The level of the new rule should be set to 1.
#     You will pick out what keys and values should be used from the received payload to create a new Wazuh
#     rule using PCRE2 syntax which can be found here: {pcre2_docs}.

#     You will pick out what keys and values should be used from the received payload to create a new Wazuh
#     rule using PCRE2 syntax and to set that level to 1. The data key field names that are applicable for use must start
#     with `data_`. Always read the `rule_id` and use that value in the newly created rule as the `<if_sid>`.
#     The created Wazuh rule should not have the `data_` in the `<field name=`. For example, the field name of `data_system_Task`
#     that is in the JSON, would be `system_Task` in the created Wazuh exclusion rule.
#     Requirements:
#         1. Replace any `_` within the `<field name=` with a `.`.
#         2. Do not use `\` to escape a `.` in the created Wazuh rule.
#         3. Always use `(?i)` to enable case insensitive matching in the created Wazuh rule.

#     Make sure to include at least 3 `<field name=` in the created Wazuh rule. If you do not think a rule requires at least 3, still
#     create the rule but state in your explanation that you recommend the SOC analyst to add more fields.
#     Wazuh Rule Syntax documentation: {rule_syntax_docs}

#     Example rules in PCRE2 syntax: {example_rules}. I want you to favor the field names: {windows_field_names_to_prefer} if these are
#     applicable. If you find that the field names are not applicable, then you can use other field names.

#     {format_instructions}


# """

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


# async def using_tools_and_agent(prompt: TestRequest):
#     logger.info(get_all_tool_names())
#     shell_tool.description = shell_tool.description + f"args {shell_tool.args}".replace(
#         "{", "{{"
#     ).replace("}", "}}")
#     self_ask_with_search = initialize_agent(
#         [shell_tool], llm, agent=AgentType.CHAT_ZERO_SHOT_REACT_DESCRIPTION, verbose=True
#     )
#     self_ask_with_search.run(
#         "Download the langchain.com webpage and grep for all urls. Return only a sorted list of them. Be sure to use double quotes."
#     )


async def load_xml_data(file_path: str):
    xml_loader = UnstructuredXMLLoader(file_path)
    return xml_loader.load()


async def load_url_data(urls: list):
    url_loader = UnstructuredURLLoader(urls=urls)
    return url_loader.load()


async def format_chat_prompt(
    prompt: TestRequest,
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
        wazuh_rule = re.sub(r'(</.*?>)', r'\1\n', wazuh_rule)  # Add a newline after every closing </>
        return explanation, wazuh_rule
    return (
        "Unfortunately, I couldn't extract the explanation and from the output. Please check the output manually.",
        extract_rule_xml_from_output(raw_output),
    )


# ! WILL RETRY WHOLE PROCESS IF ERROR ! #
async def wazuh_assistant(prompt: TestRequest, max_retries: int = 3) -> TestResponse:
    for _ in range(max_retries):
        try:
            example_rules = await load_xml_data("services/example_data.xml")
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
            return TestResponse(
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
            return TestResponse(
                wazuh_rule=wazuh_rule,
                explanation=explanation_output,
                message="Failed to parse output, returning raw XML as JSON.",
                success=True,
            )
        except Exception as e:
            logger.error(f"Attempt failed with unexpected exception: {e}")
            break
    return TestResponse(
        wazuh_rule=None,
        explanation=None,
        message="Failed to receive test message after multiple attempts.",
        success=False,
    )


async def artifact_analysis(prompt: TestRequest) -> TestResponse:
    # ! I should host an API that returns the artifacts data ...actually no ill call the velo API !
    artifact_docs = await load_url_data(
        [
            "https://docs.velociraptor.app/artifact_references/",
        ],
    )
    logger.info(f"Artifacts: {artifact_docs}")
    return None
