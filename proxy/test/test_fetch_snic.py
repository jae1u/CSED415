from proxy.fetch_snic import fetch
from proxy.interface import Request

request = Request(
    method="GET",
    url="https://www.arxiv.org/",
    header={},
    req_id=0
)
proxy_config = ("localhost", 10808)
print(fetch(request, proxy_config))