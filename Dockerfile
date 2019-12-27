FROM registry.access.redhat.com/ubi8/ruby-26
ENV HEIMDALLTOOLS_VERSION 1.3.1
MAINTAINER rx294@nyu.edu
LABEL name="Heimdall Tools" \
      vendor="MTIRE" \
      version="${HEIMDALLTOOLS_VERSION}" \
      release="1" \
      url="https://github.com/mitre/heimdall_tools" \
      description="HeimdallTools supplies several methods to convert output from various tools to \"Heimdall Data Format\"(HDF) format to be viewable in Heimdall" \
      docs="https://github.com/mitre/heimdall_tools" \
      run="docker run -d --name ${NAME} ${IMAGE} <args>"
USER 0

RUN groupadd -r heimdall_tools \
&&  useradd -r -g heimdall_tools heimdall_tools \
&&  mkdir -p /opt/app-root/ \
&&  chown -R heimdall_tools.heimdall_tools /opt/app-root/

USER heimdall_tools

RUN git clone https://github.com/mitre/heimdall_tools /opt/app-root/heimdall_tools \
&& cd /opt/app-root/heimdall_tools \
&& bundle install --path /opt/app-root/ \
&& rm -rf /opt/app-root/heimdall_tools/docs \
&& rm -rf /opt/app-root/heimdall_tools/sample_jsons 

VOLUME /opt/data
WORKDIR /opt/app-root/heimdall_tools

ENTRYPOINT ["bundle","exec","./heimdall_tools"]
