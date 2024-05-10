import configparser
import os

from loguru import logger
from pydantic import BaseModel
from pydantic import Field


class ConfigManager:
    def __init__(self, config_file_name):
        self.config = configparser.ConfigParser()

        # Determine the absolute path to the top-level directory
        base_dir = os.path.dirname(os.path.abspath(__file__))
        logger.info(f"Base directory: {base_dir}")
        self.config_file = os.path.join(base_dir, config_file_name)

        logger.debug(f"Attemping to loading config - {self.config_file}")
        self.config.read(self.config_file)

    def get(self, section, key):
        return self.config.get(section, key)

    def get_section(self, section):
        return self.config[section]

    def options(self, section):
        return self.config.options(section)


########################## ! OPENAI ! ##########################
class OpenAIModel(BaseModel):
    openai_api_key: str = Field(
        ...,
        alias="openai_api_key",
    )


def get_openai_from_config():
    config_manager = ConfigManager("config.ini")
    return OpenAIModel(
        openai_api_key=config_manager.get("OPENAI", "openai_api_key"),
    )
