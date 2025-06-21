import { DataTypes } from 'sequelize';
import sequelize from '../config/database.js';

const OAuthClient = sequelize.define('oauth_client', {
	id: {
		type: DataTypes.UUID,
		defaultValue: DataTypes.UUIDV4,
		primaryKey: true
	},
	userId: {
		type: DataTypes.STRING
	},
	// userId: {
	//     type: DataTypes.INTEGER,
	//     references: {
	//         model: User,
	//         key: 'id'
	//     }
	// },
	clientId: {
		type: DataTypes.STRING
	},
	clientSecret: {
		type: DataTypes.STRING
	},
	callbackUrl: {
		type: DataTypes.STRING
	},
	grants: {
		type: DataTypes.ARRAY(DataTypes.STRING),
		allowNull: false,
		validate: {
			isValidGrants(value) {
				const validGrants = ['authorization_code', 'refresh_token', 'password', 'client_credentials', 'implicit'];
				if (!value.every(grant => validGrants.includes(grant))) {
					throw new Error('Invalid grant type');
				}
			}
		}
	},
	scopes: {
		type: DataTypes.ARRAY(DataTypes.STRING)
	}
});

export default OAuthClient;
