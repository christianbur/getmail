FROM alpine:3.19

WORKDIR /app

ARG UID=2999
ARG GID=2999

# python3 venv: https://pythonspeed.com/articles/activate-virtualenv-dockerfile/

ENV VIRTUAL_ENV=/opt/venv

RUN apk add --update --no-cache python3 py3-pip py3-virtualenv tzdata \
    && python3 -m venv $VIRTUAL_ENV \
    && addgroup -g $GID -S appuser \
    && adduser  -u $UID -S appuser -G appuser  

ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN pip install imapclient

USER appuser

COPY getmail_imap2lmtp.py .
CMD [ "python","-u", "/app/getmail_imap2lmtp.py" ]
