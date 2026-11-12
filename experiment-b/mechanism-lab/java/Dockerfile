FROM maven:3.9-eclipse-temurin-25 AS builder
WORKDIR /build
COPY pom.xml .
COPY src ./src
RUN mvn -B -q package
FROM eclipse-temurin:25-jre
WORKDIR /app
COPY --from=builder /build/target/mechanism-lab-0.1.0-SNAPSHOT.jar /app/app.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]
