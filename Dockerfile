FROM debian:stable-slim as base

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

RUN apt-get update && \
    apt-get install --yes \
    ca-certificates \
    libolm3 \
    python3 \
    python-is-python3 \
    python3-setuptools && \
    apt-get clean


FROM base as builder
RUN apt-get update && \
    apt-get --yes install \
        libolm-dev \
        libffi-dev \
        python3-dev \
        python3-pip \
        python-is-python3 

RUN pip3 install --upgrade setuptools
RUN pip3 install --upgrade pip
RUN pip3 install --upgrade pipenv

ENV PYROOT /pyroot
ENV PYTHONUSERBASE $PYROOT
RUN mkdir -p $PYROOT
ENV PATH $PATH:$PYROOT

#WORKDIR /opt/app

COPY Pipfile* ./

#ENV PIPENV_VENV_IN_PROJECT 1
RUN pipenv --version

RUN pipenv --help

#WORKDIR /opt/app
#WORKDIR $PYTHONUSERBASE

#if lockfile is missing create it
RUN [ -f Pipfile.lock ] || pipenv lock

RUN PIP_USER=1 PIP_IGNORE_INSTALLED=1 pipenv install --system --deploy --ignore-pipfile

#
#RUN pipenv install --system --deploy
#--ignore-pipfile

FROM base as app

ENV PYROOT /pyroot
ENV PYTHONUSERBASE $PYROOT
RUN mkdir -p $PYROOT
ENV PATH $PATH:$PYROOT

COPY --from=builder $PYROOT/bin/ $PYROOT/bin/
COPY --from=builder $PYROOT/lib/ $PYROOT/lib/

WORKDIR /app

COPY app/* ./

CMD ["python3", "run.py"]