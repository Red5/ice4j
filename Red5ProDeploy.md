Deploy the artifact with the proper classifier to denote it as a Red5 Pro build.

Update the `file` and `version` as needed, the `file` is the jar which was output in the `target` directory of the build. 
The `version` is the version we want to be stored in artifactory.

```sh
mvn deploy:deploy-file -DgeneratePom=true -DrepositoryId=red5pro-ext-snapshot \
-Durl=https://red5pro.jfrog.io/red5pro/ext-snapshot-local \
-Dfile=ice4j-2.5-SNAPSHOT.jar -DgroupId=org.jitsi -DartifactId=ice4j \
-Dclassifier=red5pro \
-Dversion=2.5.1-SNAPSHOT
```
This will use your existing credentials for artifactory to do the deploy.
