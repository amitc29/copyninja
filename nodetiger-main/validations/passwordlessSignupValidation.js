import Joi from 'joi';

const passwordlessSignupValidation = Joi.object({
    email: Joi.string().email().messages({
        'string.email': 'Email must be a valid email address.'
    }),
    phone: Joi.string().pattern(/^\+?[0-9()-]*$/).min(10).messages({
        'string.pattern.base': 'Phone number must be a valid number with optional +, digits, (), or -.',
        'string.min': 'Phone number must be at least 10 digits long.'
    }),
    type:Joi.string().valid(
            "user",
            "organization"
        ).messages({
            "any.only":
            "Invalid type. Must be one of the value : user, organization."
        }),
}).xor('email', 'phone').messages({
    'object.xor': 'Either email or phone is required, but not both.'
});

export default passwordlessSignupValidation;
