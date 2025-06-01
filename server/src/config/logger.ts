import { createLogger, format, transports } from 'winston';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const logger = createLogger({
    format: format.combine(
        format.timestamp(),
        format.json()
    ),
    transports: [
        new transports.File({ 
            filename: path.join(__dirname, '../../logs/error.log'), 
            level: 'error' 
        }),
        new transports.File({ 
            filename: path.join(__dirname, '../../logs/combined.log')
        })
    ]
});

if (process.env.NODE_ENV !== 'production') {
    logger.add(new transports.Console({
        format: format.simple()
    }));
}

export default logger; 