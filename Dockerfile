# Build stage
FROM gradle:8.0-jdk17 AS build
COPY --chown=gradle:gradle . /home/gradle/project
WORKDIR /home/gradle/project
RUN gradle build -x test

# Run stage
FROM openjdk:21
COPY --from=build /home/gradle/project/build/libs/ms-auth-0.0.1-SNAPSHOT.jar demo.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "demo.jar"]