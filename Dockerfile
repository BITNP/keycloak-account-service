FROM python:3
MAINTAINER Phy <dockerfile@phy25.com>
WORKDIR /usr/src/app

# Use sed because of potential file owner issue
# RUN sed -i 's/deb.debian.org/mirror.bit.edu.cn/g' /etc/apt/sources.list && \
#     sed -i 's|security.debian.org/debian-security|mirror.bit.edu.cn/debian-security|g' /etc/apt/sources.list && \
#  　 sed -i 's|security.debian.org|mirror.bit.edu.cn/debian-security|g' /etc/apt/sources.list && \
#     apt-get update && \
#     apt-get install -y nginx supervisor && \
#     rm -rf /var/lib/apt/lists/* && \

COPY requirements.txt ./
# only update pip if requirements changed
RUN pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple && \
    pip install -r requirements.txt --no-cache

COPY . .

EXPOSE 80
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "80"]