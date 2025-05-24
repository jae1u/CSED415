from proxy.fetch_adaptive import fetch
from proxy.interface import Request

proxy_config = ("localhost", 10808)

def try_fetch(req):
    res = fetch(req, proxy_config)
    print(f"{res.status_code} {res.url}")

try_fetch(
    Request(
        method="POST",
        url="https://httpbin.org/post",
        header={
            b'content-length': b'10'
        },
        req_id=0,
        body=b'1234567890'
    )
)

try_fetch(
    Request(
        method="GET",
        url="https://www.arxiv.org/",
        header={},
        req_id=1
    )
)

try_fetch(
    Request(
        method="GET",
        url="https://httpbin.org/get",
        header={},
        req_id=2,
    )
)


try_fetch(
    Request(
        method="GET",
        url="https://www.arxiv.org/",
        header={},
        req_id=3
    )
)


