  sonarqube_mapper pulls SonarQube results, for the specified project name, from the API and outputs in HDF format Json to be viewed on Heimdall

Examples:

  heimdall_tools sonarqube_mapper -n sonar_project -u http://sonar:9000/api -o scan_results.json
