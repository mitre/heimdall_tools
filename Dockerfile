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


RUN wget https://github.com/mitre/heimdall_tools/archive/v${HEIMDALLTOOLS_VERSION}.zip \
&& unzip v${HEIMDALLTOOLS_VERSION}.zip   \
&& mv heimdall_tools-${HEIMDALLTOOLS_VERSION} heimdall_tools  \
&& cd heimdall_tools \
&& bundle install --path /opt/app-root/src \
&& rm /opt/app-root/src/v${HEIMDALLTOOLS_VERSION}.zip  \
&& rm -rf sample_jsons  \
&& rm -rf docs  

VOLUME /opt/data
WORKDIR /opt/app-root/src/heimdall_tools

ENTRYPOINT ["bundle","exec","./heimdall_tools"]
