FROM defund/crypto

COPY . /ctf
WORKDIR /ctf

RUN pip3 install -r requirements.txt

EXPOSE 3000
LABEL options='{"ports": {"3000": 19004}}'

CMD ["python3", "server.py"]