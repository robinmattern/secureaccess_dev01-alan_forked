var _FVARS = {
    "PROJECT_NO":           "55",
    "PROJECT_NAME":         "SAS",
    "PROJECT_VERSION":      "1.02" ,
    "CLIENT_PORT":          "55301",
    "CLIENT_HOST":          "http://localhost:55301",
    "SERVER_PORT":          "55351",
    "SERVER_API_URL":       "http://localhost:55351/api",

    "LOCAL_HOST":           "http://localhost:55301",
    "LOCAL_API_URL":        "http://localhost:55351/api",
//  "REMOTE_HOST":          "https://92.112.184.206:55301",
//  "REMOTE_API_URL":       "https://92.112.184.206:55351/api",
    "REMOTE_HOST":          "https://secureaccess247.com",
    "REMOTE_API_URL":       "https://secureaccess247.com/api",
    "SERVER_LOCATION":      "Local",

//  "SECURE_HOST":          "http://92.112.184.206:55351",
//  "SECURE_API_URL":       "http://92.112.184.206:55351/api",
    "SECURE_HOST":          "https://secureaccess247.com",
    "SECURE_API_URL":       "https://secureaccess247.com/api",
    "SECURE_PATH":          "https://secureaccess247.com",

    "CORS_ORIGINS": [
//    "http://92.112.184.206:55301",
      "https://secureaccess247.com",
       ]
     }
  if (typeof(window)  != 'undefined') {  window.FVARS  = _FVARS; var aGlobal = "window"  }
  if (typeof(process) != 'undefined') {  process.FVARS = _FVARS; var aGlobal = "process" }

      console.log( `${aGlobal}.FVARS:`, fmtFVARS( JSON.stringify( _FVARS, "", 2 ).split("\n") ).join("\n") )
      function fmtFVARS( mFVars ) { return mFVars.map( a => a.replace( /: "/g, `:${''.padEnd( 20 - (a.indexOf(":")) )} "` ) ) }
