module.exports = {
  apps: [
    {
      name: 'iodd-s54182',
      script: './server.mjs',
      cwd: '/webs/iodd/server3/s32_iodd-data-api',
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
      error_file: '/webs/iodd/logs/iodd-s54182_error.log',
      out_file: '/webs/iodd/logs/iodd-s54182_out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      merge_logs: true,
      time: true
    },
    
    {
      name: 'iodd-c54132',
      script: 'npx',
      args: 'http-server -c-1 -p 54132 --cors',
      cwd: '/webs/iodd/client3/c32_iodd-app',
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      watch: false,
      wait_ready: true,
      listen_timeout: 10000,
      min_uptime: '10s',
      max_restarts: 15,
      env: {
        NODE_ENV: 'production'
      },
      error_file: '/webs/iodd/logs/iodd-c54132_error.log',
      out_file: '/webs/iodd/logs/iodd-c54132_out.log',
      log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
      merge_logs: true,
      time: true
    }
  ]
};

/* Documentation
Updated the PM2 configuration to start both servers:
iodd-api (backend) - starts first
iodd-client (frontend) - serves static files on port 54132 using http-server
To use:
pm2 start ecosystem.config.js - starts both in order
pm2 restart all - restarts both
pm2 stop iodd-api or pm2 stop iodd-client - stop individually
pm2 logs - view all logs
The backend starts first automatically since it's listed first in the apps array.
*/