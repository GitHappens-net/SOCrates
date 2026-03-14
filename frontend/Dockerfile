FROM node:20-alpine

WORKDIR /app

# Copy package and lock files to install dependencies
COPY package*.json ./
RUN npm install

# Copy the rest of the frontend code
COPY . .

# Expose Vite's configured dev port
EXPOSE 5174

# Run the dev server on all network interfaces to be reachable from the host
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
