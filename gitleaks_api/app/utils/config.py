from pathlib import Path
import configparser

def get_github_config() -> dict:
    """Load GitHub configuration from config.ini."""
    config = configparser.ConfigParser()
    config_path = Path(__file__).parent.parent / "config" / "config.ini"
    
    if not config_path.exists():
        return {'token': None, 'repo': None}
        
    config.read(config_path)
    return {
        'token': config.get('github', 'token', fallback=None),
        'repo': config.get('github', 'repo', fallback=None)
    }
