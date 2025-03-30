FROM python:slim-bullseye AS app
RUN pip install --no-cache pycryptodome

FROM pwn.red/jail
COPY --from=app / /srv
COPY server.py /srv/app/run
COPY key.pem flag.txt /srv/app/
ENV JAIL_TIME=600 JAIL_MEM=20M JAIL_CPU=500
