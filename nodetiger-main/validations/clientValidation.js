import Joi from 'joi';

const clientValidation = Joi.object({
    clientId: Joi.string().required().messages({
        'any.required': 'Client ID is required.',
        'string.empty': 'Client ID cannot be empty.'
    }),
    clientSecret: Joi.string().required().messages({
        'any.required': 'Client Secret is required.',
        'string.empty': 'Client Secret cannot be empty.'
    }),
    redirectUri: Joi.string().required().messages({
        'any.required': 'Redirect URI is required.',
        'string.empty': 'Redirect URI cannot be empty.'
    }),
    grants: Joi.array().required().messages({
        'any.required': 'Grants is required.',
        'string.empty': 'Grants cannot be empty.'
    }),
    scopes: Joi.array().required().messages({
        'any.required': 'Scopes is required.',
        'string.empty': 'Scopes cannot be empty.'
    })
});

export default clientValidation;
