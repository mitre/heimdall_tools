  jfrog_xray_mapper translates an JFrog Xray results JSON file into HDF format JSON to be viewable in Heimdall
  
  A separate HDF JSON is generated for each project reported in the Xray Report.

Examples:

  heimdall_tools jfrog_xray_mapper -j xray_results.json -o output-file-name.json