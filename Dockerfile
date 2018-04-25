FROM ubuntu:16.04

RUN apt-get update -y
RUN apt-get install -y python3
RUN apt-get install -y python3-pip python3-gevent python3-virtualenv
COPY ./pip.conf /etc/pip.conf
RUN virtualenv venv -p python3
RUN . venv/bin/activate
RUN pip install -r ./requirements.txt

ENTRYPOINT gunicorn -w 4 -b 127.0.0.1:8080 app:app