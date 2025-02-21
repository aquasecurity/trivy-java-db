package com.aquasecurity.trivy_java_db;

import org.apache.lucene.index.Term;
import org.apache.lucene.search.WildcardQuery;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.FSDirectory;
import org.apache.maven.index.*;
import org.apache.maven.index.context.DefaultIndexingContext;
import org.apache.maven.index.context.IndexCreator;
import org.apache.maven.index.context.IndexingContext;
import org.apache.maven.index.creator.MinimalArtifactInfoIndexCreator;
import org.apache.maven.index.updater.IndexUpdateRequest;
import org.apache.maven.index.updater.ResourceFetcher;

import java.io.*;
import java.nio.file.Paths;
import java.util.*;
import java.util.zip.GZIPInputStream;

public class MavenIndexReader {
    public static void main(String[] args) {
        File indexDir = new File("index");
        File repoDir = new File("repo");
        File localCache = new File("local-cache");
        String cacheDir = args[0];
        if (cacheDir.isEmpty()){
            String userHome = System.getProperty("user.home");
            cacheDir = Paths.get(userHome, ".cache").toString();
        }

        // Create necessary directories
        for (File dir : new File[]{indexDir, repoDir, localCache}) {
            if (!dir.exists()) {
                dir.mkdirs();
            }
        }

        try {
            System.out.println("Initializing index reader...");

            // Setup index creators
            List<IndexCreator> indexers = new ArrayList<>();
            indexers.add(new MinimalArtifactInfoIndexCreator());

            // Create indexing context
            Directory directory = FSDirectory.open(indexDir.toPath());
            IndexingContext context = new DefaultIndexingContext(
                    "central-context",
                    "central",
                    repoDir,
                    directory,
                    null,
                    null,
                    indexers,
                    true
            );

            File archiveDir = new File(cacheDir + File.separator + "archives");
            File[] files = archiveDir.listFiles();
            if (files != null) {
                Arrays.sort(files);
            }

            if (files != null) {
                for (File file : files) {
                    if (file.isFile()) {
                        // Implement custom ResourceFetcher
                        ResourceFetcher fetcher = new ResourceFetcher() {
                            @Override
                            public void connect(String id, String url) {
                            }

                            @Override
                            public void disconnect() {
                            }

                            @Override
                            public InputStream retrieve(String name) throws IOException {
                                System.out.println("Loading index file: " + file.getAbsolutePath());
                                if (!file.exists()) {
                                    throw new FileNotFoundException("Index file not found: " + file.getAbsolutePath());
                                }
                                return new GZIPInputStream(new FileInputStream(file));
                            }
                        };

                        System.out.println("Updating indexes for " + file.getName());

                        // Execute index update
                        IndexUpdateRequest updateRequest = new IndexUpdateRequest(context, fetcher);
                        updateRequest.setLocalIndexCacheDir(localCache);
                        updateRequest.setForceFullUpdate(true);

                        // Initialize search engine
                        DefaultSearchEngine searchEngine = new DefaultSearchEngine();

                        // Create simple wildcard query for all artifacts
                        WildcardQuery query = new WildcardQuery(new Term(ArtifactInfo.GROUP_ID, "*"));

                        // Execute search
                        FlatSearchRequest searchRequest = new FlatSearchRequest(query);
                        searchRequest.setCount(-1);

                        FlatSearchResponse response = searchEngine.searchFlatPaged(
                                searchRequest,
                                Collections.singletonList(context)
                        );


                        String artifactName = "";
                        String version = "";
                        Index index = null;
                        if (response.getResults() != null) {
                            for (ArtifactInfo ai : response.getResults()) {
                                String newArtifactName = ai.getGroupId() + ":" + ai.getArtifactId();
                                if (!artifactName.equals(newArtifactName)) {
                                    // Save previous Index
                                    if (index != null){
                                        index.saveToFile(file.getName(), cacheDir);
                                    }

                                    // Init new Index
                                    artifactName = newArtifactName;
                                    version = ""; // Clear version to avoid case when 2 different artifacts have same version
                                    index = new Index(ai.getGroupId(), ai.getArtifactId());
                                }

                                // Save version. This is required to find sha1 from maven central, if index archive doesn't contain sha1.
                                if (!version.equals(ai.getVersion())){
                                    version = ai.getVersion();
                                    index.addVersion(ai.getVersion(), null);
                                }

                                // We need to keep only executable jars, so:
                                // - skip non `*.jar` files.
                                // - skip `*.source.jar`, `*.javadoc.jar`, etc. files.
                                if (!ai.getFileExtension().equals("jar") || (ai.getClassifier() != null)){
                                    // TODO handle lite|models/etc. jars
                                    continue;
                                }

                                index.addVersion(ai.getVersion(), ai.getSha1());
                            }
                        }

                        // Save last Index
                        if (index != null){
                            index.saveToFile(file.getName(), cacheDir);
                        }
                    }
                }
            }



        } catch (Exception e) {
            System.out.println("Error occurred: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

