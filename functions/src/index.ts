// The Cloud Functions for Firebase SDK to create Cloud Functions and setup triggers.
import * as functions from 'firebase-functions';

// The Firebase Admin SDK to access Cloud Firestore.
import admin = require('firebase-admin');
admin.initializeApp();

import crypto = require('crypto');

// // Start writing Firebase Functions
// // https://firebase.google.com/docs/functions/typescript

// Command for testing: curl -X POST -H "Content-Type:application/json" https://us-central1-feedtheparrot-rss.cloudfunctions.net/auth -d '{"code":"1234"}'
export const auth = functions.https.onRequest(async (request, response) => {
  if (request.is('json') && request.body.code) {
    const code : string = request.body.code;
    functions.logger.info("Code received: " + code, {structuredData: true});

    const hashedCode = crypto.createHash('md5').update(code).digest('hex');

    functions.logger.info("Hashed code: " + hashedCode, {structuredData: true});

    const codeQuery = await admin.firestore().collection('auth-codes').where('code', '==', hashedCode).limit(1).get();
    if (codeQuery.empty) {
      functions.logger.info("Bad code", {structuredData: true});
      response.status(403).send('Bad code')
    } else {
      const codeDoc = codeQuery.docs[0];
      const codeData = codeDoc.data();

      const expirationDateTimestamp: FirebaseFirestore.Timestamp = codeData.expirationDate;
      const expirationDate = expirationDateTimestamp.toDate();

      functions.logger.info("Expiration date: " + JSON.stringify(expirationDate), {structuredData: true});
      
      const now = new Date();

      functions.logger.info("Current date: " + JSON.stringify(now), {structuredData: true});

      // If the code has not expired yet, continue
      if (now < expirationDate) {
        if (hashedCode === codeData.code) {
          functions.logger.info("Good code", {structuredData: true});
          const token = await admin.auth().createCustomToken(codeData.uid);
          await codeDoc.ref.delete();
          response.send(token);
        } else {
          functions.logger.info("Good code according to database, bad code according to logic", {structuredData: true});
          response.status(409).send('There was an error. Please try again.');
        }
      } else {
        functions.logger.info("Code has expired", {structuredData: true});
        await codeDoc.ref.delete();
        response.status(403).send('The code has expired.');
      }
    }
  } else {
    response.status(400).send('Bad Request');
  }
});
