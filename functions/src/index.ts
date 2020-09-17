// The Cloud Functions for Firebase SDK to create Cloud Functions and setup triggers.
import * as functions from 'firebase-functions';

// The Firebase Admin SDK to access Cloud Firestore.
import admin = require('firebase-admin');
admin.initializeApp();

const { onCall, HttpsError } = functions.https;
const { info } = functions.logger;

// // Start writing Firebase Functions
// // https://firebase.google.com/docs/functions/typescript

export const signInWithAuthCode = onCall(async (data, context) => {
  if (data.code && typeof data.code === 'string') {
    const code : string = data.code;
    info("Code received: " + code, {structuredData: true});

    const codeQuery = await admin.firestore().collection('auth-codes').where('code', '==', code).limit(1).get();
    if (codeQuery.empty) {
      info("Bad code", {structuredData: true});
      throw new HttpsError('unauthenticated','The code was not valid.');
    } else {
      const codeDoc = codeQuery.docs[0];
      const codeData = codeDoc.data();

      const expirationDateTimestamp: FirebaseFirestore.Timestamp = codeData.expirationDate;
      const expirationDate = expirationDateTimestamp.toDate();

      info("Expiration date: " + JSON.stringify(expirationDate), {structuredData: true});
      
      const now = new Date();

      info("Current date: " + JSON.stringify(now), {structuredData: true});

      // If the code has not expired yet, continue
      if (now < expirationDate) {
        if (code === codeData.code) {
          info("Good code", {structuredData: true});
          const token = await admin.auth().createCustomToken(codeData.uid);
          await codeDoc.ref.delete();
          return token;
        } else {
          info("Good code according to database, bad code according to logic", {structuredData: true});
          throw new HttpsError('internal', 'There was an error. Please try again.');
        }
      } else {
        info("Code has expired", {structuredData: true});
        await codeDoc.ref.delete();
        throw new HttpsError('out-of-range', 'The code has expired.');
      }
    }
  } else {
    throw new HttpsError('invalid-argument', 'Bad Request. The function must be called with one string argument "code" containing the auth code.');
  }
});
