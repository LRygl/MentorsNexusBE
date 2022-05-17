FROM amazoncorretto:18
EXPOSE 8081
ADD target/mentors-nexus-backend.jar mentors-nexus-backend.jar
ENTRYPOINT ["java","-jar","/mentors-nexus-backend.jar"]