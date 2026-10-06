FROM ubuntu:26.04

RUN apt-get update && apt-get install -y socat dos2unix && rm -rf /var/lib/apt/lists/*

RUN useradd -m ctf

WORKDIR /home/ctf

COPY ./dist/rop-the-bank /home/ctf/rop-the-bank
COPY ./flag.txt /home/ctf/flag.txt
COPY ./start.sh /home/ctf/start.sh

RUN chown -R root:root /home/ctf
RUN chmod 755 /home/ctf
RUN dos2unix /home/ctf/start.sh
RUN chmod 755 /home/ctf/rop-the-bank
RUN chmod 755 /home/ctf/start.sh
RUN chmod 444 /home/ctf/flag.txt

USER ctf

EXPOSE 1337

CMD ["/home/ctf/start.sh"]