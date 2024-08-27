FROM eclipse-temurin:21-jre

WORKDIR /gateway

COPY ./target/gateway.jar /gateway/gateway.jar

EXPOSE 8080

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]