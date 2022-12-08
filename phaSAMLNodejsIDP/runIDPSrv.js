const { runAssert } = require('saml-idp');
var conf = require('saml-idp/config');
//const samlIdp = require('saml-idp');

console.log("samlIdp: " + conf.profile);
runAssert({
	  acsUrl: `https://foo.okta.com/auth/saml20/assertion-consumer`,
	  audience: `https://foo.okta.com/auth/saml20/metadata`,
	  config: {
	    user: 'Ajeet Phadnis',
	    // The auth-service requires at least one AttributeStatement in the SAML assertion.
	    metadata: [{
	      id: 'email',
	      optional: false,
	      displayName: 'E-Mail Address',
	      description: 'The e-mail address of the user',
	      multiValue: false
	    }, {
	      id: "userType",
	      optional: true,
	      displayName: 'User Type',
	      description: 'The type of user',
	      options: ['Admin', 'Editor', 'Commenter']
	    }],
	    user: {
	      email: 'Ajeet.Phadnis@phadnis.no',
	    },
	  },
	});