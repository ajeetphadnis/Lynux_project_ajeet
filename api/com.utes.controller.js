/**
 * Project: com.utes.auth.protocol.exchange
 * 
 * Module:
 * 
 * Created On:
 * 
 * 
 * 
 * 
 */
'use strict';

var properties = require('../package.json')
var convrt = require('../service/com.utes.security.convert');
var convrt_demo = require('../service/com.utes.security.convert_demo');
var userUtils = require('../models/com.utes.auth.userUtils');
var samlUtils = require('../saml_assert/com.utes.saml_auth.userUtils');
var jwksUtils = require('../jwks/com.utes.jwks.createJWKS');
var jwtUtils = require('../jwks/com.utes.jwks.jwe.createJWT');
var ocspUtils = require('../x509_utils/com.utes.verify.p12.verifyClientCerts');
var clntSecureEnv = require('../secure_envelop/com.utes.secure.env');
var protocolTrans = require('../protocolservice/com.utes.protocol.exchange');
var ecdsaUtils = require('../ecdsa_keycerts/com.utes.ec.ecdsa.crKeyCerts');




/**
 * 
 * Module: controllers
 * This module registers different collectors as requested by the router
 * 
 * @param firstname
 * @returns
 * 
 */
var controllers = {
    convrt: function(req, res) {
	  convrt.convrt(req, res);
    },
    convrt_demo: function(req, res) {
  	  convrt_demo.convrt_demo(req, res);
    },
    protocolconvert_start: function(req, res) {
    	userUtils.protocolconvert_start(req, res);
    },
    profile_user: function(req, res) {
    	userUtils.profile_user(req, res);
    },
    login_user: function(req, res) {
    	userUtils.login_user(req, res);
    },
    register_user: function(req, res) {
    	userUtils.register_user(req, res);
    },
    nav_side: function(req, res) {
    	userUtils.nav_side(req, res);
    },
    getDemoUserSAMLAssert: function(req, res) {
    	samlUtils.getDemoUserSAMLAssert(req, res);
    },
    getDemoUserJWKSets: function(req, res) {
    	jwksUtils.getDemoUserJWKSets(req, res);
    },
    getDemoUserJWT: function(req, res) {
    	jwtUtils.getDemoUserJWT(req, res);
    },
    utesdemo: function(req, res) {
    	userUtils.utesdemo(req, res);
    },
    demo_user: function(req, res) {
    	userUtils.demo_user(req, res);
    },
    getDemoUserOCSP: function(req, res) {
    	ocspUtils.getDemoUserOCSP(req, res);
    },
    getDemoUserSecureEnv: function(req, res) {
    	clntSecureEnv.getDemoUserSecureEnv(req, res)
    },
    sendEmail:function(req, res) {
    	userUtils.sendEmail(req, res);
    },
    setSAMLAssert:function(req, res) {
        userUtils.setSAMLAssert(req, res);
    },
    getProtocolTrans:function(req, res) {
        protocolTrans.getProtocolTrans(req, res);
    },
	getEcDsaKeysCerts: function(req, res) {
    	ecdsaUtils.getEcDsaKeysCerts(req, res);
    },
};

module.exports = controllers;
