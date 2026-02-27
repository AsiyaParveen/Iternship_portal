import sys
import os

# Add the project directory to the sys.path so the app module can be found
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app
