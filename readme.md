rust reimplementation of the following server app
https://github.com/zoom/zoomapps-texteditor-vuejs


# Installation

```shell
apt-get install -y openssl libssl-dev
```


# Docker

## Build

```shell
docker build -t rust-api:0.0.1 .
```

## Run

```shell
docker run --rm -it \
        -p 3000:3000 \
        -e ZM_CLIENT_ID=$ZM_CLIENT_ID \
        -e ZM_CLIENT_SECRET=$ZM_CLIENT_SECRET \
        -e ZM_REDIRECT_URL=$ZM_REDIRECT_URL \
        -e PROXY_TARGET=$PROXY_TARGET \
        -e ZOOM_APP_PORT=$ZOOM_APP_PORT \
        rust-api:0.0.1
```
