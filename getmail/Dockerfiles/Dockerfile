FROM alpine:3.11

WORKDIR /app

ARG UID=2999
ARG GID=2999

RUN apk add --no-cache python3 tzdata \
    && python3 -m pip install --upgrade pip \
    && python3 -m pip install imapclient configparser \
    && addgroup -g $GID -S appuser \
    && adduser  -u $UID -S appuser -G appuser  

USER appuser

COPY ./getmail_imap2lmtp.py ./

CMD [ "python3","-u", "./getmail_imap2lmtp.py" ]
