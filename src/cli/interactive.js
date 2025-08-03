#!/usr/bin/env node

/**
 * @fileoverview Interactive Mode for FlareInspect
 * @description Provides an interactive shell for FlareInspect commands
 * @module cli/interactive
 */

const readline = require('readline');
const { spawn } = require('child_process');
const chalk = require('chalk');
const { displayBanner, displayCredits } = require('./utils/banner');

// Create readline interface
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: chalk.cyan('flareinspect> ')
});

// Display banner on startup
displayBanner();

// Show available commands
console.log(chalk.yellow('Available Commands:'));
console.log(chalk.gray('  assess    - Run a Cloudflare security assessment'));
console.log(chalk.gray('  export    - Export assessment results'));
console.log(chalk.gray('  help      - Display help information'));
console.log(chalk.gray('  credits   - Display IONSEC.IO information'));
console.log(chalk.gray('  clear     - Clear the screen'));
console.log(chalk.gray('  exit      - Exit interactive mode'));
console.log();
console.log(chalk.gray('Type a command to get started. For example: help'));
console.log();

// Show prompt
rl.prompt();

// Handle line input
rl.on('line', (line) => {
  const input = line.trim();
  
  if (!input) {
    rl.prompt();
    return;
  }

  // Handle built-in commands
  switch (input.toLowerCase()) {
    case 'exit':
    case 'quit':
      console.log(chalk.yellow('\nGoodbye! Thank you for using FlareInspect.'));
      process.exit(0);
      break;
      
    case 'clear':
    case 'cls':
      console.clear();
      displayBanner();
      rl.prompt();
      break;
      
    case 'credits':
      displayCredits();
      rl.prompt();
      break;
      
    default:
      // Execute flareinspect command
      const args = input.split(' ');
      const child = spawn(process.execPath, [require.resolve('../cli/index.js'), ...args], {
        stdio: 'inherit',
        env: { ...process.env, FORCE_COLOR: '1', FLAREINSPECT_INTERACTIVE: 'child' }
      });
      
      child.on('close', (code) => {
        console.log(); // Add newline after command output
        rl.prompt();
      });
      
      child.on('error', (err) => {
        console.error(chalk.red('Error executing command:'), err.message);
        rl.prompt();
      });
  }
});

// Handle Ctrl+C
rl.on('SIGINT', () => {
  console.log(chalk.yellow('\n\nGoodbye! Thank you for using FlareInspect.'));
  process.exit(0);
});

// Handle close
rl.on('close', () => {
  console.log(chalk.yellow('\nGoodbye! Thank you for using FlareInspect.'));
  process.exit(0);
});