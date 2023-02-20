# Miakapp Server

Server that allows the connection between Miakapp users and the coordinator.

## Installation

1. Install dependencies

    ```sh
    npm i
    ```

2. Configuration

    Create a `./config` directory and a `./config/config.js` file. Write this inside the file:

    ```js
    module.exports = {
      SERVER_URL: 'miakapi-example1.domain.com',
      SERVER_NAME: 'NAME - Region - Country',
      FIREBASE_CREDENTIAL: {
        type: 'service_account',
        project_id: '<FIREBASE_PROJECT_ID>',
        private_key_id: '<FIREBASE_PRIVATE_KEY_ID>',
        private_key: '<FIREBASE_PRIVATE_KEY>'
        client_email: '<FIREBASE_CLIENT_EMAIL>',
        client_id: '<FIREBASE_CLIENT_ID>',
      },
    };
    ```

## For Docker

1. Build

    ```sh
    npm run build
    ```

2. Run

    ```sh
    docker run 
    ```

## For Docker Compose

```sh
docker-compose up
```
