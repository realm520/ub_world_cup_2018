FROM ubuntu:16.04

RUN apt-get update -y
RUN apt-get install -y python3
RUN apt-get install -y python3-pip python3-gevent python3-virtualenv
RUN /usr/bin/pip3 install virtualenv
COPY ./pip.conf /etc/pip.conf
RUN /usr/bin/pip3 install -r ./requirements.txt
RUN apt-get install -y nodejs npm redis-server
RUN npm install web3 web3-eth
RUN export production=True

ENTRYPOINT gunicorn -w 4 -b 127.0.0.1:8080 app:app