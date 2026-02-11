module.exports = {
  apps: [
    {
      name: 'SAS-s55151',
      script: './server.js',
      cwd: '/Users/Shared/repos/SAS_/dev01-alan/server/s01_server-first-api',
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      watch: false,
      max_memory_restart: '1G',
      min_uptime: '10s',
      max_restarts: 15,
      env: {
        NODE_ENV: 'production'
      },
      error_file: '/Users/Shared/repos/SAS_/logs/SAS-s55151_error.log',
      out_file:   '/Users/Shared/repos/SAS_/logs/SAS-s55151_out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      merge_logs: true,
      time: true
    },
    
    {
      name: 'SAS-c55101',
      script: 'npx',
      args: 'http-server -c-1 -p 55101 --cors',
      cwd: '/Users/Shared/repos/SAS_/dev01-alan/client/c01_client-first-app',
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      watch: false,
      min_uptime: '10s',
      max_restarts: 15,
      env: {
        NODE_ENV: 'production'
      },
      error_file: '/Users/Shared/repos/SAS_/logs/SAS-c55101_error.log',
      out_file:   '/Users/Shared/repos/SAS_/logs/SAS-c55101_out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      merge_logs: true,
      time: true
    }
  ]
};
