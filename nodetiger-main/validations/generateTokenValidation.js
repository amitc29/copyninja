import Joi from 'joi';

const generateTokenValidation = Joi.object({
    grant_type: Joi.string().valid('password', 'refresh_token').required().messages({
        'any.required': 'Grant type is required.',
        'any.only': 'Invalid grant type. Must be one of the values: password, refresh_token.',
        'valid.base': 'Invalid grant type. Must be one of the values: password, refresh_token.'
    }),
    refresh_token: Joi.when('grant_type', {
        is: 'refresh_token',
        then: Joi.string().required().messages({
            'any.required': 'Refresh token is required.',
        })
    }),
    email: Joi.when('grant_type', {
        is: 'password',
        then: Joi.string().email().messages({
            'any.required': 'Either email or phone is required when grant type is password.',
            'string.email': 'Email must be a valid email address.'
        })
    }),
    phone: Joi.when('grant_type', {
        is: 'password',
        then: Joi.string().pattern(/^\+?[0-9()-]*$/).min(10).messages({
            'string.pattern.base': 'Phone number must be a valid number with optional +, digits, (), or -.',
            'string.min': 'Phone number must be at least 10 digits long.'
        })
    }),
    password: Joi.when('grant_type', {
        is: 'password',
        then: Joi.string().required().messages({
            'any.required': 'Password is required.',
            'string.empty': 'Password cannot be empty.'
        })
    })
}).messages({
    'object.and': 'Refresh token is required when grant type is refresh_token.'
});

export default generateTokenValidation;
