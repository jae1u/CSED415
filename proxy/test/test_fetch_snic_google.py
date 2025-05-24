from proxy.fetch_snic import fetch
from proxy.interface import Request

request = Request(
    method="GET",
    url="https://www.google.com/",
    header={

    },
    req_id=0
)
proxy_config = ("localhost", 10808)
res = fetch(request, proxy_config)
print(res.status_code, res.url)