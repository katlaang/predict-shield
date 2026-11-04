FROM maven:3.9-eclipse-temurin-25 AS build
WORKDIR /workspace
COPY pom.xml .
COPY src ./src
RUN mvn -B -q -DskipTests package

FROM eclipse-temurin:25-jre
WORKDIR /app
COPY --from=build /workspace/target/access-lab-0.1.0-SNAPSHOT.jar /app/access-lab.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/access-lab.jar"]
