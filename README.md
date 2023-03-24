# Miakapp Server

Server that allows the connection between Miakapp users and the coordinator.

## Development

1. Install dependencies

    ```sh
    npm i
    ```

2. Configuration

    Create a `.env` file or set env variables:

    ```properties
    SERVER_URL=miakapi-example1.domain.com
    SERVER_NAME=Name (Region, Country)
    FIREBASE_CREDENTIALS={"type":"service_account", ...}
    ```

    `SERVER_URL` and `SERVER_NAME` are optional.

## Deployment with Docker Compose (Traefik)

```yml
version: '3'

services:
  miakapp-server:
    image: ghcr.io/miakapp/miakapp-server:latest
    restart: always
    environment:
      SERVER_URL: ${SERVER_URL}
      SERVER_NAME: ${SERVER_NAME}
      FIREBASE_CREDENTIALS: ${FIREBASE_CREDENTIALS}
    labels:
      - 'traefik.enable=true'
      - 'traefik.http.routers.miakapp.rule=Host(`${SERVER_URL}`)'
      - 'traefik.http.routers.miakapp.entrypoints=https'

networks:
  default:
    name: traefik_web
    external: true
```
