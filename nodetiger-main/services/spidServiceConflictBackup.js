import { customAlphabet } from 'nanoid';

<<<<<<< HEAD
// Generate an 12 digit unique SPID number
export function generateSPIDNumber(type=null, level=null) {

    const alphabet = "0123456789";
    let spid = '';

    if (type) {
        let prefix = "";
        if (type === 'School') {
            prefix = 20;
        } else if (type === 'University') {
            prefix = 21;
        } else if (type === 'College') {
            prefix = 22;
        } else if (type === 'Academy') {
            prefix = 23;
        } else if (type === 'Sport Organisation') {
            if (level === 'Town') {
                prefix = 24;
            } else if (level === 'City') {
                prefix = 25;
            } else if (level === 'District') {
                prefix = 26;
            } else if (level === 'State') {
                prefix = 27;
            } else if (level === 'National') {
                prefix = 28;
            } else if (level === 'International') {
                prefix = 29;
            }
        } else if (type === "Other") {
            prefix = 19;
        }
        const nanoid = customAlphabet(alphabet, 10);
        const randomNumber = nanoid();
        spid = `${prefix}${randomNumber}`.match(/.{1,4}/g).join("-");
    } else {
        const nanoid = customAlphabet(alphabet, 12);
        const randomNumber = nanoid();
        spid = randomNumber.match(/.{1,4}/g).join("-");
    }
    return spid;
}
=======
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

        if (type === 'Sport Organisation') {
            // For Sport Organisation, use the level prefix
            prefix = levelPrefixMap[level];
            if (!prefix) {
                throw new Error('Invalid level category');
            }
        } else {
            // For other types, use the type prefix
            prefix = typePrefixMap[type];
            if (!prefix) {
                throw new Error('Invalid type category');
            }
        }

        // Generate 10 random digits
        const alphabet = '0123456789';
        const nanoid = customAlphabet(alphabet, 10);
        const randomNumber = nanoid();
        
        // Combine the prefix and the random number
        const spid = prefix + randomNumber;
        
        // Format SPID with hyphens
        const formattedSpid = spid.match(/.{1,4}/g).join('-');

        return formattedSpid;
    } catch (error) {
        console.error(`Error generating SPID number: ${error.message}`);
        throw error; // Re-throw the error to propagate it
    }
}


>>>>>>> 2555b43bf0e67f307ab0d4e332557f12ef877e07
