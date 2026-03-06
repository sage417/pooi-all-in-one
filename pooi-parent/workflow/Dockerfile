FROM eclipse-temurin:21-jre-alpine

# RUN apk add --no-cache curl

WORKDIR /app

COPY package.jar /app/app.jar

EXPOSE 8080

ENV JAVA_OPTS="-Xmx2048m -Dfile.encoding=UTF-8 -Duser.timezone=Asia/Shanghai -Dserver.port=8080"

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app/app.jar"]

HEALTHCHECK --interval=30s --timeout=5s --retries=3 --start-period=30s\
  CMD curl -f -s http://localhost:8080/actuator/health | grep -q '"status":"UP"' || exit 1
