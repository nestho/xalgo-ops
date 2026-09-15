FROM projectdiscovery/nuclei:latest
USER root
RUN apk add --no-cache nodejs npm || true
WORKDIR /worker
COPY package.json server.js ./
ENV PORT=8787
EXPOSE 8787
CMD ["node", "server.js"]
