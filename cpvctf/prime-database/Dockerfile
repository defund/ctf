FROM ubuntu

RUN apt-get update
RUN apt-get install -y xinetd python3 python3-pip
RUN pip3 install pycryptodome

COPY prime_database.py local.py primes.txt /ctf/
WORKDIR /ctf/

COPY xinetd /etc/xinetd.d/ctf
COPY run.sh .
RUN chmod +x run.sh

EXPOSE 8000

CMD ["/bin/sh", "-c", "service xinetd restart && sleep infinity"]
