FROM alpine

RUN apk add --no-cache \
	gcc \
	g++ \
	libffi-dev \
	openssl-dev \
	python3-dev \
	git \
	openssl \
	python3

COPY requirements.txt /
RUN pip3 install -r /requirements.txt

ADD . /
ENTRYPOINT python3 -u crawler.py