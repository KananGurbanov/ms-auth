FROM gradle:8.0-jdk17 AS build
COPY --chown=gradle:gradle . /home/gradle/src
WORKDIR /home/gradle/src
RUN gradle build --no-daemon

##########

FROM openjdk:17-jdk-slim
EXPOSE 8081
RUN mkdir /app
ENV TZ=UTC
COPY --from=build /home/gradle/src/build/libs/*.jar /app/app.jar
ENTRYPOINT ["java", "-jar", "/app/app.jar"]  
