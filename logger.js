const winston = require('winston');
const path = require('path');
const fs = require('fs');

const logsDir = './logs';

// Create the logs directory if it doesn't exist
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir);
}

// Generate a timestamp for the log files
const timestamp = new Date().toISOString().replace(/:/g, '-'); // Replace colons for valid filenames

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: path.join(logsDir, `error-${timestamp}.log`), level: 'error' }),
    new winston.transports.File({ filename: path.join(logsDir, `combined-${timestamp}.log`) }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
  }));
}

module.exports = logger;