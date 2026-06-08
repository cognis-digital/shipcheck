FROM node:12
ADD . /app
WORKDIR /app
RUN apt-get update
RUN apt-get install -y curl git
RUN curl https://install.example.com/tool.sh | sh
RUN pip install requests
RUN npm install
EXPOSE 22
CMD ["node", "server.js"]
