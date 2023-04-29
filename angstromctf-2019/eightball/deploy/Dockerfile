FROM defund/crypto

COPY . /ctf
WORKDIR /ctf

EXPOSE 3000
LABEL options='{"ports": {"3000": 19000}}'

CMD ["python3", "server.py"]