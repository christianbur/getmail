FROM alpine:3.16

WORKDIR /app

ARG UID=2999
ARG GID=2999

RUN apk add --update --no-cache python3 py3-pip tzdata \
    && addgroup -g $GID -S appuser \
    && adduser  -u $UID -S appuser -G appuser  

USER appuser

ENV PATH="/home/appuser/.local/bin:${PATH}"

RUN python3 -m pip install --user --upgrade pip \
    && python3 -m pip install --user imapclient configparser 

COPY ./getmail_imap2lmtp.py /app/


CMD [ "python3","-u", "/app/getmail_imap2lmtp.py" ]
