#!/usr/bin/env node

/**
 * @fileoverview Welcome script for FlareInspect Docker
 * @description Shows banner and usage instructions
 * @module cli/welcome
 */

const chalk = require('chalk');
const { displayBanner } = require('./utils/banner');

// Display banner
displayBanner();

// Show quick start guide
console.log(chalk.yellow('Quick Start Guide:'));
console.log();
console.log(chalk.white('Run an assessment:'));
console.log(chalk.green('  docker run -v $(pwd):/app/output flareinspect assess --token YOUR_TOKEN'));
console.log();
console.log(chalk.white('Generate HTML report:'));
console.log(chalk.green('  docker run -v $(pwd):/app/output flareinspect export -i assessment.json -o report.html -f html'));
console.log();
console.log(chalk.white('Interactive shell:'));
console.log(chalk.green('  docker run -it flareinspect sh'));
console.log();
console.log(chalk.white('View help for any command:'));
console.log(chalk.green('  docker run flareinspect help [command]'));
console.log();
console.log(chalk.gray('For more information: https://github.com/ionsec/flareinspect'));
console.log();