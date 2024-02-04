FROM python:3.11.1-slim-bullseye AS app
RUN pip install --no-cache pycryptodome

FROM pwn.red/jail:0.3.1
COPY --from=app / /srv
COPY server.py /srv/app/run
COPY flag.txt /srv/app/
ENV JAIL_MEM=20M JAIL_CPU=500
