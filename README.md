# CSED415
---
*Include a comprehensive README that explains how to build, configure, and execute your project to reproduce your results.*

You need a tunnel, like v2ray.

SNIC is coded with python and can be run by using a python interpreter. After cloning the [SNIC repository](https://github.com/jae1u/CSED415), run the following command in the project root directory to start SNIC.

```bash
python -m proxy.proxy
```

**왜 인증서 과정이 필요한지 적어줘!!!**

```bash
cd ./proxy
openssl genrsa -out rootCA.key 2048
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 3650 \
  -out rootCA.crt \
  -subj "/C=KR/ST=Seoul/O=MyProxy/CN=MyRootCA"
```
To use this certificate in your browser, you need to import the `rootCA.crt` file into your browser's trusted certificate store. Then, you need to configure your browser to use your proxy server.

If you are using Firefox, you can use
- `settings > Privacy & Security > Certificates > View Certificates > Authorities > Import` to import the `rootCA.crt` file.
- `settings > General > Network Settings > Settings > Manual proxy configuration` to set up your proxy server

If you are using Chrome, you can use
- `settings > Prvacy and security > Security > Manage certificates > Custom (Installed by you) > Import` to import the `rootCA.crt` file.
- `settings > System > Open your computer's proxy settings` to set up your proxy server. (Chrome uses the system proxy settings)

Otherwise, you can use command line launch options like:
```bash
chromium --proxy-server="http=localhost:11556;https=localhost:11556"
```


