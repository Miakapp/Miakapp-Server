module.exports = {
  apps: [{
    name: 'Miakapp Server',
    script: 'main.js',
    max_memory_restart: '300M',
    watch: '.',
  }],

  deploy: {
    production: {
      user: 'main',
      host: '192.168.0.1',
      ref: 'origin/main',
      repo: 'git@github.com:Miakapp/Miakapp-Server.git',
      path: '/home/main/MiakappV3',
      ssh_options: 'StrictHostKeyChecking=no',
      'pre-deploy-local': '',
      'post-deploy': 'npm i && pm2 reload ecosystem.config.js --env production',
      'pre-setup': '',
    },
  },
};
