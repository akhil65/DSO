FROM bkimminich/juice-shop:latest

# Switch to root to install OpenRASP agent
USER root

# Install OpenRASP Node.js agent
# openrasp-node is the Baidu OpenRASP agent for Node.js apps
RUN npm install -g @baidu/openrasp --unsafe-perm 2>/dev/null || \
    npm install /tmp/openrasp-node 2>/dev/null || true

# Copy OpenRASP configuration
COPY openrasp.yml /juice-shop/openrasp.yml

# Copy the entrypoint wrapper that injects the RASP agent before app start
COPY rasp-entrypoint.sh /rasp-entrypoint.sh
RUN chmod +x /rasp-entrypoint.sh

# Juice Shop runs on port 3000
EXPOSE 3000

# Use wrapper entrypoint — injects OpenRASP via NODE_OPTIONS before starting app
ENTRYPOINT ["/rasp-entrypoint.sh"]
