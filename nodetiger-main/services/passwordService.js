import bcrypt from 'bcryptjs';

const saltRounds = 10;

// Generating a password
export async function generatePassword(password) {
    return await bcrypt.hash(password, saltRounds);
}

// Comparing a passwords
export async function compareHashAndPassword(password, hashedPassword) {
    return await bcrypt.compare(password, hashedPassword);
}