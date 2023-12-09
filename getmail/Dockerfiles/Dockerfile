FROM alpine:3.19

WORKDIR /app

# python3 venv: https://pythonspeed.com/articles/activate-virtualenv-dockerfile/

ENV VIRTUAL_ENV=/opt/venv

RUN apk add --update --no-cache python3 py3-pip py3-virtualenv tzdata \
    && python3 -m venv $VIRTUAL_ENV 

ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN pip install imapclient configparser

COPY getmail_imap2lmtp.py .
CMD [ "python","-u", "/app/getmail_imap2lmtp.py" ]
