FROM oraclelinux:8-slim

RUN  microdnf install oracle-instantclient-release-el8 && \
     microdnf install oracle-instantclient-basic && \
     microdnf install gcc  \
                      oracle-instantclient-release-el8 \
                      oracle-instantclient-basic \
                      openldap-devel \
                      python39 \
                      python39-libs \
                      python39-devel \
                      python39-pip \
                      python39-setuptools && \
     microdnf clean all

WORKDIR /

COPY *.py /
COPY requirements.txt /
COPY ldap.ora /usr/lib/oracle/21/client64/lib/network/admin/ldap.ora
COPY sqlnet.ora /usr/lib/oracle/21/client64/lib/network/admin/sqlnet.ora

RUN python3 -m pip install --no-cache-dir -r requirements.txt

EXPOSE 1976

CMD [ "python3", "main.py" ]