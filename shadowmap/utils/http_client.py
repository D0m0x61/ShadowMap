import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from shadowmap.config import Config


def get_session(retries: int = None, backoff: float = None) -> requests.Session:
    retries = retries if retries is not None else Config.HTTP_RETRIES
    backoff = backoff if backoff is not None else Config.HTTP_BACKOFF

    session = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))
    session.headers.update({
        "User-Agent": Config.USER_AGENT,
        "Accept": "application/json",
    })
    return session
