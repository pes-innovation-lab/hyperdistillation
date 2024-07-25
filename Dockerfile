# syntax=docker/dockerfile:1
FROM alpine
RUN apk add curl
RUN apk add --update --no-cache python3
RUN ln -sf python3 /usr/bin/python