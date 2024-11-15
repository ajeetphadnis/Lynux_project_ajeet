FROM node:20.7
# Create app directory
WORKDIR com.utes.auth.protocol.exchange_new
COPY /com.utes.auth.protocol.exchange_new/package*.json .
COPY . .
RUN npm install
EXPOSE 30010:30010
EXPOSE 30082:30082
# RUN cd /com.utes.auth.protocol.exchange_new
# CMD [ "node" ,  "pha_authExchangeSrv.js" ]
