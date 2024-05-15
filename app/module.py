import uvicorn
from app.routes.ai import ai_router
from fastapi import FastAPI
from loguru import logger

app = FastAPI(description="Copilot-AI-Module", version="0.0.1")

app.include_router(ai_router)

logger.debug("Starting SOCFortress AI Module Application")


@app.get("/")
def hello():
    return {"message": "Module - We Made It!"}


if __name__ == "__main__":
    logger.info("Starting SOCFortress AI Module Application")
    uvicorn.run(app, host="0.0.0.0", port=80)
