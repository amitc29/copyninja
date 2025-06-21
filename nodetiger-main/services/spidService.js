import { customAlphabet } from 'nanoid';
import logger from "../config/logger.js";

// Mapping of prefixes for each organisation type, when choosing sport organization we don't get any prefix instead we get prefix for levels therefore adding two different prefixes

// Prefixes for different levels
const levelPrefixMap = {
    'Town': '24',
    'City': '25',
    'District': '26',
    'State': '27',
    'National': '28',
    'International': '29',
};

// Prefixes for other types
const typePrefixMap = {
    'School': '20',
    'University': '21',
    'College': '22',
    'Academy': '23',
    'Other': '19',
};


// Generate a 12 digit unique SPID number with a prefix
export function generateSPIDNumber(type, level) {
    try {
        let prefix = '';
        let spid = '';

        if (type) {
            if (type === "Sport Organisation") {
                // For Sport Organisation, use the level prefix
                prefix = levelPrefixMap[level];
                if (!prefix) {
                throw new Error("Invalid level category");
                }
            } else {
                // For other types, use the type prefix
                prefix = typePrefixMap[type];
                if (!prefix) {
                throw new Error("Invalid type category");
                }
            }

            // Generate 10 random digits
            const alphabet = "0123456789";
            const nanoid = customAlphabet(alphabet, 10);
            const randomNumber = nanoid();

            // Combine the prefix and the random number
            spid = prefix + randomNumber;
        } else {
            // Generate 12 random digits
            const alphabet = "0123456789";
            const nanoid = customAlphabet(alphabet, 12);
            const randomNumber = nanoid();

            // Combine the prefix and the random number
            spid = randomNumber;
        }

        // Format SPID with hyphens
        const formattedSpid = spid.match(/.{1,4}/g).join('-');

        // logger.info(`Generated SPID number: ${formattedSpid}`);
        return formattedSpid;
    } catch (error) {
        logger.error(`Error generating SPID number: ${error.message}`);
        throw error; // Re-throw the error to propagate it
    }
}


