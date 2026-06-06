import os
import yaml  # Αλλαγή από json σε yaml
import logging

# Basic logging configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config(config_path="config.yaml"): # Προεπιλογή το αρχείο σου στο root
    """
    Loads configuration from a YAML file.
    """
    try:
        with open(config_path, 'r') as f:
            # Χρήση safe_load για αρχεία YAML
            config = yaml.safe_load(f)
        logging.info(f"Configuration loaded successfully from {config_path}")
        return config
    except FileNotFoundError:
        logging.error(f"Configuration file not found at {config_path}")
        return None
    except yaml.YAMLError as e: # Αλλαγή του error handling
        logging.error(f"Error decoding YAML from the configuration file at {config_path}: {e}")
        return None