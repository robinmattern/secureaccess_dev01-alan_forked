var _FVARS = {
    "PROJECT_NO":           "55",
    "PROJECT_NAME":         "SAS",
    "PROJECT_VERSION":      "1.02" ,
    "CLIENT_PORT":          "55101",
    "CLIENT_HOST":          "http://localhost:55101",
    "SERVER_PORT":          "55151",
    "SERVER_API_URL":       "http://localhost:55151/api",

    "LOCAL_HOST":           "http://localhost:55101",
    "LOCAL_API_URL":        "http://localhost:55151/api",
//  "REMOTE_HOST":          "https://92.112.184.206:55101",
//  "REMOTE_API_URL":       "https://92.112.184.206:55151/api",
    "REMOTE_HOST":          "https://secureaccess247.com",
    "REMOTE_API_URL":       "https://secureaccess247.com/api",
    "SERVER_LOCATION":      "Local",

    "SECURE_HOST":          "http://localhost:55151",
    "SECURE_API_URL":       "http://localhost:55151/api",
    "SECURE_PATH":          "http://localhost:55151/api",
//  "SECURE_HOST":          "https://secureaccess247.com",
//  "SECURE_API_URL":       "https://secureaccess247.com/api",
//  "SECURE_PATH":          "https://secureaccess247.com",

    "SECURE_API_SECRET": process.env.SECURE_API_SECRET || null,
    "IODD_APP_KEY": process.env.IODD_APP_KEY || null,
    "ALLOWED_APPS": ["IODD"],

    "CORS_ORIGINS": [
      "http://localhost:55101",
      "http://127.0.0.1:55101",
      "http://localhost:55151",
      "http://127.0.0.1:55151",
//    "https://secureaccess247.com",
       ]
     }
  if (typeof(window)  != 'undefined') {  window.FVARS  = _FVARS; var aGlobal = "window"  }
  if (typeof(process) != 'undefined') {  
      process.FVARS = _FVARS; 
      var aGlobal = "process";
      
      // Log security configuration status
      if (!_FVARS.SECURE_API_SECRET) {
          console.warn('⚠️  SECURE_API_SECRET not set in environment');
      }
      if (!_FVARS.IODD_APP_KEY) {
          console.warn('⚠️  IODD_APP_KEY not set in environment');
      }
  }

      console.log( `${aGlobal}.FVARS:`, fmtFVARS( JSON.stringify( _FVARS, "", 2 ).split("\n") ).join("\n") )
      function fmtFVARS( mFVars ) { return mFVars.map( a => a.replace( /: "/g, `:${''.padEnd( 20 - (a.indexOf(":")) )} "` ) ) }
