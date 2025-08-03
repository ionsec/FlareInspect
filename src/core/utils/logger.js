/**
 * @fileoverview Logger utility for FlareInspect
 * @module core/utils/logger
 */

const winston = require('winston');
const chalk = require('chalk');
const path = require('path');
const fs = require('fs');

// Ensure logs directory exists
const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Custom format for console output
const consoleFormat = winston.format.printf(({ level, message, timestamp, ...metadata }) => {
  let msg = message;
  
  // Apply color based on level
  switch (level) {
    case 'error':
      msg = chalk.red(msg);
      break;
    case 'warn':
      msg = chalk.yellow(msg);
      break;
    case 'info':
      msg = chalk.blue(msg);
      break;
    case 'debug':
      msg = chalk.gray(msg);
      break;
    case 'success':
      msg = chalk.green(msg);
      break;
  }
  
  // Add metadata if present
  if (Object.keys(metadata).length > 0 && metadata.constructor === Object) {
    msg += ' ' + chalk.gray(JSON.stringify(metadata));
  }
  
  return msg;
});

// Create logger instance
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
  ),
  defaultMeta: { service: 'flareinspect' },
  transports: [
    // File transport for all logs
    new winston.transports.File({
      filename: path.join(logsDir, 'flareinspect.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 5
    }),
    // File transport for errors
    new winston.transports.File({
      filename: path.join(logsDir, 'error.log'),
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5
    })
  ]
});

// Add console transport only if not in quiet mode
if (process.env.QUIET_MODE !== 'true') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format((info) => {
        info.level = info.level.toUpperCase();
        return info;
      })(),
      consoleFormat
    )
  }));
}

// Custom log levels
logger.success = function(message, meta) {
  logger.log('info', chalk.green('✓ ' + message), meta);
};

logger.fail = function(message, meta) {
  logger.log('error', chalk.red('✗ ' + message), meta);
};

logger.step = function(message, meta) {
  logger.log('info', chalk.cyan('→ ' + message), meta);
};

logger.assessment = function(message, meta) {
  logger.log('info', chalk.magenta('🔍 ' + message), meta);
};

logger.cloudflare = function(message, meta) {
  logger.log('debug', chalk.blue('☁️  ' + message), meta);
};

// Progress logging
logger.progress = function(current, total, message) {
  const percentage = Math.round((current / total) * 100);
  const progressBar = generateProgressBar(percentage);
  logger.log('info', `${progressBar} ${percentage}% - ${message}`);
};

// Generate progress bar
function generateProgressBar(percentage) {
  const filled = Math.round(percentage / 5);
  const empty = 20 - filled;
  return chalk.green('█'.repeat(filled)) + chalk.gray('░'.repeat(empty));
}

module.exports = logger;