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
const fs = require('fs');
const controller = require('./com.utes.controller');


/**
 * Module: router app
 * 
 * 
 * 
 * @param firstname
 * @returns
 * 
 */
module.exports = function(app) {
	const bodyParser = require('body-parser');
	app.use(bodyParser.urlencoded({ extended: true }));
    //app.route('/execServ').get(controller.execServ);
    //app.route('/postServ').post(controller.postServ);
    app.route('/convrt').get(controller.convrt);
    app.route('/convrt').post(controller.convrt);
    app.route('/convrt_demo').get(controller.convrt_demo);
    app.route('/convrt_demo').post(controller.convrt_demo);
    app.route('/protocolconvert_start').get(controller.protocolconvert_start);
    app.route('/protocolconvert_start').post(controller.protocolconvert_start);
    app.route('/profile_user').get(controller.profile_user);
    app.route('/profile_user').post(controller.profile_user);
    app.route('/login_user').get(controller.login_user);
    app.route('/login_user').post(controller.login_user);
    app.route('/register_user').get(controller.register_user);
    app.route('/register_user').post(controller.register_user);
    app.route('/nav_side').get(controller.nav_side); 
    app.route('/getDemoUserSAMLAssert').get(controller.getDemoUserSAMLAssert);
    app.route('/getDemoUserSAMLAssert').post(controller.getDemoUserSAMLAssert);
    app.route('/getDemoUserJWKSets').get(controller.getDemoUserJWKSets);
    app.route('/getDemoUserJWKSets').post(controller.getDemoUserJWKSets);
    app.route('/getDemoUserJWT').get(controller.getDemoUserJWT);
    app.route('/getDemoUserJWT').post(controller.getDemoUserJWT);
    app.route('/demo_user').get(controller.demo_user);
    app.route('/demo_user').post(controller.demo_user);
    app.route('/utesdemo').get(controller.utesdemo);
    app.route('/utesdemo').post(controller.utesdemo);
    app.route('/getDemoUserOCSP').get(controller.getDemoUserOCSP);
    app.route('/getDemoUserOCSP').post(controller.getDemoUserOCSP);
    app.route('/getDemoUserSecureEnv').get(controller.getDemoUserSecureEnv);
    app.route('/getDemoUserSecureEnv').post(controller.getDemoUserSecureEnv);
    app.route('/getProtocolTrans').get(controller.getProtocolTrans);
    app.route('/getProtocolTrans').post(controller.getProtocolTrans);
	app.route('/getEcDsaKeysCerts').get(controller.getEcDsaKeysCerts);
    app.route('/getEcDsaKeysCerts').post(controller.getEcDsaKeysCerts);
    app.route('/index').get( function(req, res, next) {
	    res.render('index');
	 });
    app.route('/getDoc1').get( function (req, res, next) {
        var filePath = "demo_docs/RegisterOrCreateUser.pdf";    
        fs.readFile(filePath, (err, data) => {
            res.set({
              "Content-Type": "application/pdf", //here you set the content type to pdf
              "Content-Disposition": "inline; filename=" + filePath, //if you change from inline to attachment if forces the file to download but inline displays the file on the browser
            });
            res.send(data); // here we send the pdf file to the browser
            //res.render('getDoc1');
        });
    });

    app.route('/getDoc2').get( function (req, res, next) {
        var filePath = "demo_docs/UTES_IN_ACTION.pdf";    
        fs.readFile(filePath, (err, data) => {
            res.set({
              "Content-Type": "application/pdf", //here you set the content type to pdf
              "Content-Disposition": "inline; filename=" + filePath, //if you change from inline to attachment if forces the file to download but inline displays the file on the browser
            });
            res.send(data); // here we send the pdf file to the browser
            //res.render('getDoc1');
        });
    });

    app.route('/getDoc3').get( function (req, res, next) {
        var filePath = "demo_docs/RakshAboutDoc.pdf";    
        fs.readFile(filePath, (err, data) => {
            res.set({
              "Content-Type": "application/pdf", //here you set the content type to pdf
              "Content-Disposition": "inline; filename=" + filePath, //if you change from inline to attachment if forces the file to download but inline displays the file on the browser
            });
            res.send(data); // here we send the pdf file to the browser
            //res.render('getDoc1');
        });
    });

    app.route('/getDoc4').get( function (req, res, next) {
        var filePath = "demo_docs/SupportedExchanges.pdf";    
        fs.readFile(filePath, (err, data) => {
            res.set({
                "Content-Type": "application/pdf", //here you set the content type to pdf
                "Content-Disposition": "inline; filename=" + filePath, //if you change from inline to attachment if forces the file to download but inline displays the file on the browser
            });
            res.send(data); // here we send the pdf file to the browser
            //res.render('getDoc1');
        });
    });
    app.route('/index').post( function(req, res, next) {
	    res.render('index');
	 });
    app.route('/sendEmail').post(controller.sendEmail);

    app.route('/setSAMLAssert').get(controller.setSAMLAssert);
    app.route('/setSAMLAssert').post(controller.setSAMLAssert);

};