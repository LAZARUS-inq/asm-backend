FROM python:3.12-slim

WORKDIR /code

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    supervisor \
    wget \
    unzip \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.6/subfinder_2.6.6_linux_amd64.zip \
    && unzip subfinder_2.6.6_linux_amd64.zip \
    && mv subfinder /usr/local/bin/ \
    && rm subfinder_2.6.6_linux_amd64.zip

RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.2.4/nuclei_3.2.4_linux_amd64.zip \
    && unzip nuclei_3.2.4_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.2.4_linux_amd64.zip

RUN git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates.git /nuclei-templates \
    && echo "Templates cloned: $(find /nuclei-templates -name '*.yaml' | wc -l) yaml files"

ENV NUCLEI_TEMPLATES_DIRECTORY=/nuclei-templates

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]