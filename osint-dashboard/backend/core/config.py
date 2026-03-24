"""Application configuration for API keys loaded from environment variables."""

import os

from dotenv import load_dotenv

# Load variables from a local .env file (if present) into process environment.
# A .env file stores local configuration values outside source code.
load_dotenv()

# API keys are read from environment variables to avoid hardcoding secrets in code.
HIBP_API_KEY = os.getenv("HIBP_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
HUNTER_API_KEY = os.getenv("HUNTER_API_KEY")  # Optional

if not HIBP_API_KEY:
    raise ValueError("HIBP_API_KEY is not set in environment variables")
