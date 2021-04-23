ARG GO_VERSION=1.16.3
ARG REPO_NAME=""
ARG APP_NAME="iamlive"
ARG APP_PATH="/go/src/iamlive"


# Dev
FROM golang:${GO_VERSION}-alpine AS dev
RUN apk add --update git
ARG APP_NAME
ARG APP_PATH
ENV APP_NAME="${APP_NAME}" \
    APP_PATH="${APP_PATH}" \
    GOOS="linux"
WORKDIR "${APP_PATH}"
COPY . "${APP_PATH}"
ENTRYPOINT ["sh"]


# Build
FROM dev as build
RUN go install
ENTRYPOINT [ "sh" ]

# App
FROM alpine:3.12 AS app
RUN apk --update upgrade && \
    apk add --update ca-certificates && \
    update-ca-certificates
WORKDIR "/app/"
COPY --from=build "/go/bin/iamlive" ./iamlive
RUN addgroup -S "appgroup" && adduser -S "appuser" -G "appgroup" && \
    chown -R "appuser:appgroup" .

USER "appuser"
EXPOSE 10080
ENTRYPOINT ["./iamlive"]
CMD ""
