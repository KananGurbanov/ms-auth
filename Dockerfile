# Stage 1: Build the application using Gradle
FROM gradle:8.0 AS build
WORKDIR /app

# Copy build.gradle and other required files for Gradle build
COPY build.gradle settings.gradle gradlew gradle/wrapper ./gradle/

# Copy source files
COPY src src

# Run the Gradle build
RUN ./gradlew clean build -x test

# Stage 2: Create the final Docker image using OpenJDK 21
FROM openjdk:21-jdk
VOLUME /tmp

# Copy the JAR from the build stage
COPY --from=build /app/build/libs/*.jar app.jar

# Set the entry point for the application
ENTRYPOINT ["java", "-jar", "/app.jar"]

# Expose port 8081
EXPOSE 8081
