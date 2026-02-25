FROM eclipse-temurin:21-jre-alpine

WORKDIR /app

COPY target/package.jar /app/app.jar

EXPOSE 8080

ENV JAVA_OPTS="-Xmx2048m -Dfile.encoding=UTF-8 -Duser.timezone=Asia/Shanghai -Dserver.port=8080"

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app/app.jar"]

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
  CMD wget -q -O - http://localhost:8080/actuator/health || exit 1
