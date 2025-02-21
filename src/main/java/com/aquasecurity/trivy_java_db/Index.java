package com.aquasecurity.trivy_java_db;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.io.File;
import java.io.IOException;
import java.util.HashMap;

public class Index { // Used to save indexes to json
    public String groupID;
    public String artifactID;
    public String archiveType;

    public Index(String groupID, String artifactID) {
        this.groupID = groupID;
        this.artifactID = artifactID;
        this.archiveType = "jar"; // Only `jar` archives are supported now.
    }

    public HashMap<String, String> versions = new HashMap<>();

    public void addVersion(String version, String sha1){
        this.versions.put(version, sha1 != null ? sha1 : "");
    }

    public void saveToFile(String archiveName, String cacheDir) throws IOException {
        String archiveDir = archiveName.substring(0, archiveName.lastIndexOf(".gz"));
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.enable(SerializationFeature.INDENT_OUTPUT);

        // TODO use custom path for indexes
        String filePath = cacheDir + File.separator + "indexes" + File.separator + archiveDir
                + File.separator + this.groupID + File.separator + this.artifactID + ".json";

        File file = new File(filePath);
        file.getParentFile().mkdirs();

        objectMapper.writeValue(file, this);
    }
}
