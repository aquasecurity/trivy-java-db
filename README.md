# trivy-java-db

## Overview
`trivy-java-db` parses all indexes from [maven repository](https://repo.maven.apache.org/maven2) and stores `ArtifactID`, `GroupID`, `Version` and `sha1` for jar files to SQlite DB.

The DB is used in Trivy to discover information about `jars` without GAV inside them.

## Update interval
Every Thursday in 00:00

## Download the java indexes database
You can download the actual compiled database via [Oras CLI](https://oras.land/cli/).

oras >= v0.13.0:
```sh
$ oras pull ghcr.io/aquasecurity/trivy-java-db:1
```

oras < v0.13.0:
```sh
$ oras pull -a ghcr.io/aquasecurity/trivy-java-db:1
```
The database can be used for [Air-Gapped Environment](https://aquasecurity.github.io/trivy/latest/docs/advanced/air-gap/).