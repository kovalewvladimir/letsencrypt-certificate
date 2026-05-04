FROM debian:13

ENV TZ=Europe/Moscow
RUN apt-get update \
    && apt-get install -y tzdata \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime \
    && echo $TZ > /etc/timezone \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update \
    && apt-get install -y golang make git curl \
    && rm -rf /var/lib/apt/lists/*

# Set `DEVCONTAINER` environment variable to help with orientation
ENV DEVCONTAINER=true