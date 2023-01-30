# trivy-java-db

## Overview
`trivy-java-db` parses all indexes from [maven repository](https://repo.maven.apache.org/maven2) and stores `ArtifactID`, `GroupID`, `Version` and `sha1` for jar files to SQlite DB.

The DB is used in Trivy to discover information about `jars` without GAV inside them.
 