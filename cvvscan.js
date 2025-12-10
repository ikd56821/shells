const fs = require('fs');
const path = require('path');

class SensitiveInfoScanner {
    constructor(hostIdentifier = null) {
        this.regexPatternsMethod1 = [
            /[0-9a-z]+\.execute-api\.[0-9a-z._-]+\.amazonaws\.com/,
            /AKIA[0-9A-Z]{16}/,
            /arn:aws:[a-z0-9-]+:[a-z]{2}-[a-z]+-[0-9]+:[0-9]+:.+/,
            /(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/,
            /da2-[a-z0-9]{26}/,
            /amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/,
            /s3:\/\/[0-9a-z._/-]+/,
            /(aws_access_key_id|aws_secret_access_key)/,
            /\b(LTAI[a-z0-9]{10,128})["'\s;]*/,
            /((access)(|-|_)(key)(|-|_)(id|secret))/i,
            /R_[0-9a-f]{32}/,
            /(?:bitly).{0,40}\b([a-zA-Z-0-9]{40})\b/,
            /(?:circle).{0,40}([a-fA-F0-9]{40})/,
            /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/,
            /(sk_|sk_test_)[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/,
            /\b(api[_-]?key|access[_-]?key|private[_-]?key)\s*[=:]\s*['"]?([a-zA-Z0-9+/=]{8,128})['"]?/i,
        ];
        
        this.keywordsMethod2 = [
            'card_number','cvv','cc_number','cardnumber','cardno','card_num',
            'cardnum','credit_card_number','card_digits','card_identifier',
            'expirydate','expiry_date','expiry','expdate','exp_date','expirymonth',
            'expiry_month','expirationmonth','expiration_month','expiryyear',
            'expiry_year','expirationyear','expiration_year','expmonth','exp_month',
            'expyear','exp_year','cvv2','cvvcode','cid','securitycode','security_code',
            'seccode','sec_code','card_security_code','cardtype','card_type','cardbrand',
            'card_brand','firstname','first_name','holdername','holder_name'
        ];
        
        this.includedExtensions = [
            'php', 'jsp', 'java', 'class', 'properties', 'yaml', 'xml', 'js', 'mjs', 'cjs'
        ];
        
        this.excludedDirectories = [
            'vendor', 'wp-admin', 'wp-includes', 'node_modules', '.git', 'phpmyadmin', 'example'
        ];
        
        this.MAX_FILE_CHARS = 1024000;
        
        this.countMethod1 = 0;
        this.countMethod2 = 0;
        this.resultsBuffer = [];
        this.hostIdentifier = hostIdentifier || 'localhost';
    }

    async scanDirectory(directory = '/') {
        this.countMethod1 = 0;
        this.countMethod2 = 0;
        this.resultsBuffer = [];
        
        await this.scanRecursive(directory, true);
        
        if (this.resultsBuffer.length > 0) {
            await this.sendResults();
        }
        
        return {
            method1: this.countMethod1,
            method2: this.countMethod2
        };
    }

    async scanRecursive(currentPath, isRoot = false) {
        try {
            if (!fs.existsSync(currentPath) || !fs.lstatSync(currentPath).isDirectory()) {
                return;
            }
            
            const lowerPath = currentPath.toLowerCase();
            if (lowerPath.includes('cache') || lowerPath.includes('lang')) {
                return;
            }
            
            const items = fs.readdirSync(currentPath);
            
            for (const item of items) {
                if (item === '.' || item === '..') continue;
                
                const fullPath = path.join(currentPath, item);
                if (fs.lstatSync(fullPath).isDirectory()) {
                    if (!this.isExcludedDirectory(item)) {
                        await this.scanRecursive(fullPath);
                    }
                } else if (fs.lstatSync(fullPath).isFile() && this.isReadableFile(fullPath)) {
                    await this.checkFile(fullPath);
                }
            }
        } catch (error) {
            console.error(`Error scanning directory ${currentPath}:`, error.message);
        }
    }

    isExcludedDirectory(dirname) {
        return this.excludedDirectories.includes(dirname.toLowerCase());
    }

    isReadableFile(filePath) {
        try {
            fs.accessSync(filePath, fs.constants.R_OK);
            return true;
        } catch {
            return false;
        }
    }

    async checkFile(filePath) {
        try {
            if (!this.shouldScanFile(filePath)) {
                return;
            }

            if (this.isBinaryFile(filePath)) {
                return;
            }

            let content = '';
            try {
                const fd = fs.openSync(filePath, 'r');
                const buffer = Buffer.alloc(this.MAX_FILE_CHARS);
                const bytesRead = fs.readSync(fd, buffer, 0, this.MAX_FILE_CHARS, 0);
                fs.closeSync(fd);
                content = buffer.toString('utf8', 0, bytesRead);
            } catch {
                return;
            }

            for (const pattern of this.regexPatternsMethod1) {
                const match = content.match(pattern);
                if (match) {
                    this.addToBuffer({
                        host: this.hostIdentifier,
                        path: filePath,
                        content: Buffer.from(content).toString('base64'),
                        search_method: 1,
                        matched_pattern: pattern.toString()
                    });
                    this.countMethod1++;
                    break;
                }
            }

            if (this.hasIncludedExtension(filePath)) {
                let count = 0;
                const foundKeywords = [];
                
                const lowerContent = content.toLowerCase();
                
                for (const keyword of this.keywordsMethod2) {
                    if (lowerContent.includes(keyword.toLowerCase())) {
                        count++;
                        foundKeywords.push(keyword);
                        if (count >= 3) {
                            this.addToBuffer({
                                host: this.hostIdentifier,
                                path: filePath,
                                content: Buffer.from(content).toString('base64'),
                                search_method: 2,
                                matched_pattern: foundKeywords.join(', ')
                            });
                            this.countMethod2++;
                            break;
                        }
                    }
                }
            }
        } catch { }
    }

    shouldScanFile(filePath) {
        if (this.hasIncludedExtension(filePath)) {
            return true;
        }
        return path.basename(filePath).toLowerCase() === '.env';
    }

    hasIncludedExtension(filePath) {
        const extension = path.extname(filePath).toLowerCase().slice(1);
        return this.includedExtensions.includes(extension);
    }

    addToBuffer(result) {
        this.resultsBuffer.push(result);
    }

    async sendResults() {
        console.log("===== Local scan results (network disabled) =====");

        for (const r of this.resultsBuffer) {
            console.log(`\n[FILE] ${r.path}`);
            console.log(`[MATCH] ${r.matched_pattern}`);
            console.log(`[METHOD] ${r.search_method}`);
            console.log(`[CONTENT BASE64]\n${r.content}`);
        }

        console.log("\n===== End of results =====");

        this.resultsBuffer = [];
    }

    isBinaryFile(filePath) {
        try {
            const buffer = Buffer.alloc(1024);
            const fd = fs.openSync(filePath, 'r');
            const bytesRead = fs.readSync(fd, buffer, 0, buffer.length, 0);
            fs.closeSync(fd);

            for (let i = 0; i < bytesRead; i++) {
                if (buffer[i] === 0) return true;
            }
            return false;
        } catch {
            return false;
        }
    }
}

async function main() {
    const hostIdentifier = process.argv[2] || 'localhost';
    const scanner = new SensitiveInfoScanner(hostIdentifier);

    console.log('Starting scan...');

    const rootDir = process.platform === 'win32' ? 'C:\\' : '/';
    const results = await scanner.scanDirectory(rootDir);

    console.log('Scan completed:');
    console.log(`Method 1 matches: ${results.method1}`);
    console.log(`Method 2 matches: ${results.method2}`);

    if (scanner.resultsBuffer.length > 0) {
        await scanner.sendResults();
    }
}

if (require.main === module) {
    main();
}

module.exports = SensitiveInfoScanner;
