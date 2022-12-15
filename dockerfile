FROM node:14.16.0

# Create app directory
WORKDIR ./

# Install app dependencies
# A wildcard is used to ensure both package.json AND package-lock.json are copied
# where available (npm@5+)
COPY package*.json ./

RUN npm install
# If you are building your code for production
# RUN npm install --only=production

# Bundle app source
COPY . .
# docker build -t e_convert .
# docker run --publish 3443:3443 e_convert
EXPOSE 3443

CMD ["npm", "start"]