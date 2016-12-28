FROM ubuntu

RUN apt-get update && apt-get install -y \
    make \
    gcc

ADD srf-ip-conn /usr/local/srf-ip-conn

RUN cd /usr/local/srf-ip-conn && \
    make -C client-demo
    
ENTRYPOINT [ "/usr/local/srf-ip-conn/client-demo/client" ]
    
