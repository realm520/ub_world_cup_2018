FROM ubuntu:16.04

RUN apt-get update -y
RUN apt-get install -y python3
RUN apt-get install -y python3-pip python3-gevent python3-virtualenv
RUN /usr/bin/pip3 install virtualenv
COPY ./pip.conf /etc/pip.conf
COPY ./requirements.txt /requirements.txt
RUN /usr/bin/pip3 install -r /requirements.txt
RUN apt-get install -y nodejs npm redis-server
