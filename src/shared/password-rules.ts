export function checkComplexity(plainPassword: string) : string[] {
    const errors: string[] = [];
    if (plainPassword.length < 8) {
        errors.push("Password must be at least 8 characters");
    }
    if (!plainPassword.match(/[a-z]/)) {
        errors.push("Password must contain at least one lowercase letter");
    }
    
    return errors;
}