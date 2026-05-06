FROM postgres:16

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        postgresql-server-dev-16 \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /pgsigchain
COPY . .

RUN make clean && make && make install

# Init script to create the extension on startup
RUN echo "CREATE EXTENSION pgsigchain;" > /docker-entrypoint-initdb.d/00-pgsigchain.sql
