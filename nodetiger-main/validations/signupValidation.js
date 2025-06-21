import Joi from 'joi';

const signupValidation = Joi.object({
    email: Joi.string().email().messages({
        'string.email': 'Email must be a valid email address.'
    }),
    phone: Joi.string().pattern(/^\+?[0-9()-]*$/).min(10).messages({
        'string.pattern.base': 'Phone number must be a valid number with optional +, digits, (), or -.',
        'string.min': 'Phone number must be at least 10 digits long.'
    }),
    password: Joi.string().required().messages({
        'any.required': 'Password is required.',
        'string.empty': 'Password cannot be empty.'
    })
}).xor('email', 'phone').messages({
    'object.xor': 'Either email or phone is required, but not both.'
});

export default signupValidation;
