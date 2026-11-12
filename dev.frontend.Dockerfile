FROM nginx:1.30-alpine@sha256:583b7f2fce1cdb8da5ad5c39ebd3c33b98b87d493190e548bdee1fa8c619c311

# Static files: readable by the nginx worker, writable by nobody
COPY frontend/ /usr/share/nginx/html/
RUN find /usr/share/nginx/html -type d -exec chmod 755 {} + \
  && find /usr/share/nginx/html -type f -exec chmod 644 {} +

# The image's entrypoint renders the template (${TOR_IP}) into conf.d/default.conf at start;
# an unset TOR_IP leaves an invalid allow rule and nginx refuses to start
COPY nginx.conf /etc/nginx/templates/default.conf.template
COPY nginx-site.conf /etc/nginx/elyrn/site.conf
COPY nginx-api-proxy.conf /etc/nginx/elyrn/api-proxy.conf
COPY nginx-api-errors.conf /etc/nginx/elyrn/api-errors.conf

# Unprivileged ports: compose runs nginx as uid 101 with no capability (8080 clearnet, 8081 onion)
EXPOSE 8080 8081

CMD ["nginx", "-g", "daemon off;"]
