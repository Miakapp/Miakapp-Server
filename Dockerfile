FROM node:lts-hydrogen

WORKDIR /app
COPY package*.json ./

RUN npm ci --only=production

COPY . .

RUN npm install
EXPOSE 3000

CMD ["npm", "start"]
