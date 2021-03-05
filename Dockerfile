FROM ruby:2-alpine as builder

LABEL name="Heimdall Tools" \
      vendor="MTIRE" \
      version="${HEIMDALLTOOLS_VERSION}" \
      release="1" \
      url="https://github.com/mitre/heimdall_tools" \
      description="HeimdallTools supplies several methods to convert output from various tools to \"Heimdall Data Format\"(HDF) format to be viewable in Heimdall" \
      docs="https://github.com/mitre/heimdall_tools" \
      run="docker run -d --name ${NAME} ${IMAGE} <args>"

RUN mkdir -p /share
RUN apk add --no-cache build-base git-lfs openssl-dev

COPY . /build
RUN cd /build && \
      bundle install && \
      gem build heimdall_tools.gemspec -o heimdall_tools.gem


FROM ruby:2-alpine

RUN apk add --no-cache build-base

COPY --from=builder /build/heimdall_tools.gem /build/
RUN gem install build/heimdall_tools.gem

RUN apk del build-base

ENTRYPOINT ["heimdall_tools"]
VOLUME ["/share"]
WORKDIR /share
