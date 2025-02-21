FROM maven:3.9-amazoncorretto-8 AS builder

WORKDIR /app
COPY pom.xml .
COPY src ./src/
RUN mvn clean package

FROM amazoncorretto:8-alpine

WORKDIR /app
COPY --from=builder /app/target/maven-index-reader-1.0-SNAPSHOT-jar-with-dependencies.jar ./app.jar
COPY nexus-maven-repository-index.872.gz ./nexus-maven-repository-index.872
RUN mkdir -p index repo local-cache && \
    chmod 777 index repo local-cache

CMD ["java", "-jar", "app.jar"]