// Serveur de paiement en ligne pour SmartFinance (tontines + Premium), via
// E-Billing (Digitech Africa).
//
// Reecrit a partir de la VRAIE spec OpenAPI du compte marchand (lab.billing-
// easy.net/api-docs/v1/swagger.yaml), pas d'une integration de reference
// generique — cette spec a revele un fonctionnement different de ce qui
// avait ete suppose au depart :
//   - Authentification : OAuth2 client-credentials (Cognito), PAS de Basic
//     Auth avec Username/SharedKey (celle-ci n'est acceptee que 3 mois,
//     legacy, et bypasse les scopes).
//   - Mobile money : PAS de page de paiement/checkout a ouvrir dans une
//     WebView. Le flux est 100% API : on cree une facture (invoice), puis on
//     declenche un "USSD push" — E-Billing envoie directement une invite
//     USSD sur le telephone du payeur, qui valide depuis son propre menu
//     operateur. On n'a plus qu'a attendre la confirmation (webhook + geste
//     verifie via l'endpoint d'enquete GET).
//   - Carte bancaire (CyberSource "Unified Checkout") : necessite d'heberger
//     le SDK JS CyberSource sur une page web et de gerer un "capture
//     context" — hors scope ici, pas implemente (mobile money uniquement).
//
// Pourquoi un serveur separe : le client_secret E-Billing ne doit jamais
// vivre dans l'app Flutter. Firebase Cloud Functions aurait ete l'endroit
// naturel pour ca, mais necessite le plan payant Blaze. Ce serveur Node
// independant, deployable gratuitement (Render/Railway), initie le paiement,
// recoit le webhook, RE-VERIFIE le statut aupres d'E-Billing lui-meme
// (jamais confiance dans le contenu brut du webhook), puis ecrit dans
// Firestore avec les droits d'administrateur.
//
// Ce serveur ne fait PARTIE d'aucun build Flutter : c'est un projet Node
// independant, a deployer separement. Voir README.md pour le deploiement.
//
// ATTENTION — points a reverifier aupres du compte marchand reel :
//   1. Les URLs de base 'staging'/'production' sont deduites par analogie
//      avec 'lab.billing-easy.net' (confirme par la spec) — a confirmer
//      quand des accès staging/production existeront.
//   2. La cle de signature des webhooks (X-Signature) : la spec confirme le
//      format HMAC-SHA256 mais pas OU trouver cette cle dans le tableau de
//      bord marchand (probablement distincte du client_secret). Sans elle,
//      la verification de signature est desactivee (voir
//      EBILLING_WEBHOOK_SIGNING_KEY) et on s'appuie uniquement sur la
//      re-verification via l'endpoint GET d'enquete — deja une protection
//      solide en soi, mais ajoute la cle des que tu l'as trouvee.
//   3. L'URL de notification (notification_url) et son format exact des
//      champs (notification_params) se configurent dans le tableau de bord
//      marchand, pas par requete — a renseigner toi-meme avec les chemins
//      /api/tontine/ebilling/notify et /api/premium/ebilling/notify de ce
//      serveur une fois deploye.
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const crypto = require('crypto');
const admin = require('firebase-admin');

const {
  PORT = 3000,
  EBILLING_CLIENT_ID,
  EBILLING_CLIENT_SECRET,
  // 'lab' (bac a sable, par defaut), 'staging' ou 'production'.
  EBILLING_ENV = 'lab',
  // Optionnelle : voir l'avertissement n°2 ci-dessus.
  EBILLING_WEBHOOK_SIGNING_KEY,
  PUBLIC_BACKEND_URL,
  FIREBASE_SERVICE_ACCOUNT,
} = process.env;

if (!EBILLING_CLIENT_ID || !EBILLING_CLIENT_SECRET || !PUBLIC_BACKEND_URL || !FIREBASE_SERVICE_ACCOUNT) {
  console.error(
    'Variables d\'environnement manquantes. Copie .env.example en .env et remplis-le ' +
      '(voir README.md).'
  );
  process.exit(1);
}

// Seule 'lab' est confirmee par la spec reelle — voir avertissement n°1.
const EBILLING_ENVIRONMENTS = {
  lab: 'https://lab.billing-easy.net',
  staging: 'https://stg.billing-easy.com',
  production: 'https://www.billing-easy.com',
};
const EBILLING_API_BASE = EBILLING_ENVIRONMENTS[EBILLING_ENV] || EBILLING_ENVIRONMENTS.lab;

admin.initializeApp({
  credential: admin.credential.cert(JSON.parse(FIREBASE_SERVICE_ACCOUNT)),
});
const db = admin.firestore();

const app = express();
app.use(cors());
// `verify` capture le corps brut (avant parsing) pour la verification de
// signature HMAC des webhooks, qui porte sur le corps exact tel qu'envoye.
app.use(express.json({ verify: (req, _res, buf) => { req.rawBody = buf.toString('utf8'); } }));
app.use(express.urlencoded({ extended: false, verify: (req, _res, buf) => { req.rawBody = buf.toString('utf8'); } }));

// Verifie le jeton Firebase envoye par l'app (header "Authorization: Bearer
// <idToken>") et attache l'uid VERIFIE a req.uid — jamais un uid envoye tel
// quel dans le corps de la requete, qui permettrait de se faire passer pour
// quelqu'un d'autre.
async function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const idToken = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!idToken) {
    return res.status(401).json({ error: 'Authentification requise.' });
  }
  try {
    const decoded = await admin.auth().verifyIdToken(idToken);
    req.uid = decoded.uid;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Jeton invalide ou expire.' });
  }
}

function sanitizeForTransactionId(value) {
  return String(value).replace(/[^a-zA-Z0-9]/g, '').slice(0, 20);
}

// Log le detail complet d'une erreur axios (statut + corps de reponse) —
// `err.response?.data || err.message` seul affichait juste "Request failed
// with status code 406" quand E-Billing renvoie un corps vide, sans dire
// pourquoi (mauvais format de numero, operateur incorrect, etc.).
function logAxiosError(label, err) {
  console.error(
    label,
    'status=', err.response?.status,
    'data=', JSON.stringify(err.response?.data),
    'message=', err.message
  );
}

// ---------------------------------------------------------------------------
// Authentification OAuth2 (Cognito, client-credentials) — un jeton est
// mis en cache en memoire et reutilise jusqu'a ~1 minute avant son
// expiration, pour ne pas en redemander un a chaque appel.
// ---------------------------------------------------------------------------
let cachedToken = null;
let cachedTokenExpiresAt = 0;

async function getEbillingToken() {
  if (cachedToken && cachedTokenExpiresAt > Date.now() + 60_000) {
    return cachedToken;
  }
  const res = await axios.post(
    `${EBILLING_API_BASE}/oauth/token`,
    new URLSearchParams({
      grant_type: 'client_credentials',
      client_id: EBILLING_CLIENT_ID,
      client_secret: EBILLING_CLIENT_SECRET,
    }),
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
  );
  cachedToken = res.data.access_token;
  const expiresInSeconds = Number(res.data.expires_in) || 55 * 60;
  cachedTokenExpiresAt = Date.now() + expiresInSeconds * 1000;
  return cachedToken;
}

async function ebillingRequest(method, path, { data, params } = {}) {
  const token = await getEbillingToken();
  return axios({
    method,
    url: `${EBILLING_API_BASE}${path}`,
    data,
    params,
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
  });
}

// Cree une facture (invoice/e_bill) — le montant et la reference externe
// viennent TOUJOURS du serveur (jamais du client), voir chaque appelant.
async function createInvoice({ amount, payerName, payerPhone, description, externalReference }) {
  const res = await ebillingRequest('post', '/api/v1/merchant/e_bills', {
    data: {
      amount,
      payer_msisdn: payerPhone,
      payer_name: payerName,
      short_description: description,
      external_reference: externalReference,
      client_transaction_id: externalReference,
      email: false,
      sms: false,
      expiry_period: 24, // heures
    },
  });
  const billId = res.data?.bill_id;
  if (!billId) {
    throw new Error("Reponse E-Billing invalide (bill_id manquant).");
  }
  return billId;
}

// Declenche l'invite USSD (mobile money) sur le telephone du payeur — c'est
// CA qui demarre reellement le paiement, pas la creation de facture seule.
// `operator` : 'AIRTEL' | 'MOOV' (voir payment_system_name dans la spec).
async function triggerUssdPush({ billId, operator, payerPhone }) {
  const res = await ebillingRequest('post', `/api/v2/merchant/e_bills/${encodeURIComponent(billId)}/ussd_push`, {
    data: {
      payment_system_name: operator,
      payer_msisdn: payerPhone,
    },
  });
  const ussdPush = res.data?.ussd_push;
  if (!ussdPush?.id) {
    throw new Error("Reponse E-Billing invalide (ussd_push.id manquant).");
  }
  return ussdPush;
}

// Re-interroge l'etat reel du push USSD — jamais sur la seule foi du contenu
// du webhook, qui pourrait etre forge par n'importe qui connaissant l'URL de
// notification.
async function getUssdPushStatus(ussdPushId) {
  const res = await ebillingRequest('get', `/api/v2/merchant/ussd_push/${encodeURIComponent(ussdPushId)}`);
  return res.data;
}

// Verification de signature HMAC (defense en profondeur) — voir
// l'avertissement n°2 en tete de fichier. Retourne `null` si aucune cle
// n'est configuree (verification desactivee, on s'appuie alors uniquement
// sur getUssdPushStatus ci-dessus), `true`/`false` sinon.
function verifyWebhookSignature(req) {
  if (!EBILLING_WEBHOOK_SIGNING_KEY) return null;
  const signature = req.headers['x-signature'];
  const timestamp = req.headers['x-signature-timestamp'];
  if (!signature || !timestamp) return false;
  const bodyHash = crypto.createHash('sha256').update(req.rawBody || '').digest('hex');
  const payload = `${timestamp}.${req.method}.${req.originalUrl}.${bodyHash}`;
  const expected = crypto.createHmac('sha256', EBILLING_WEBHOOK_SIGNING_KEY).update(payload).digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// 1) Tontines — initier un paiement : l'app appelle cette route quand le
//    participant a choisi son operateur et tape "Payer en ligne". Le montant
//    vient de la tontine cote SERVEUR (jamais du client). Cree la facture ET
//    declenche immediatement le push USSD (deux appels E-Billing).
// ---------------------------------------------------------------------------
app.post('/api/tontine/init-payment', requireAuth, async (req, res) => {
  try {
    const { tontineId, roundIndex, payerName, payerPhone, operator } = req.body;
    const uid = req.uid;
    if (!tontineId || roundIndex === undefined || !payerPhone || !operator) {
      return res.status(400).json({ error: 'Parametres manquants.' });
    }

    const tontineSnap = await db.collection('tontines').doc(tontineId).get();
    if (!tontineSnap.exists) {
      return res.status(404).json({ error: 'Tontine introuvable.' });
    }
    const tontine = tontineSnap.data();
    if (!Array.isArray(tontine.participantUids) || !tontine.participantUids.includes(uid)) {
      return res.status(403).json({ error: "Cet utilisateur ne fait pas partie de cette tontine." });
    }

    const amount = Math.round(Number(tontine.contributionAmount));
    const externalReference = `tt${sanitizeForTransactionId(tontineId)}r${roundIndex}${sanitizeForTransactionId(
      uid
    )}${Date.now()}`;

    const billId = await createInvoice({
      amount,
      payerName: payerName || 'Participant',
      payerPhone,
      description: `Cotisation tontine ${tontine.name} - tour ${Number(roundIndex) + 1}`,
      externalReference,
    });
    const ussdPush = await triggerUssdPush({ billId, operator, payerPhone });

    await db.collection('pendingOnlinePayments').doc(externalReference).set({
      tontineId,
      uid,
      roundIndex: Number(roundIndex),
      amount,
      billId,
      ussdPushId: String(ussdPush.id),
      createdAt: admin.firestore.Timestamp.now(),
    });

    res.json({ transactionId: externalReference, ussdPushId: String(ussdPush.id) });
  } catch (err) {
    logAxiosError('init-payment error:', err);
    if (err.response?.status === 406) {
      const detail = err.response.data || {};
      return res.status(406).json({
        error:
          detail.message ||
          detail.operator_response ||
          "Le prestataire de paiement a refuse l'operation. Verifie le format du numero " +
            "(indicatif pays sans '+' ni '0' initial, ex: 24177xxxxxxx) et que l'operateur choisi correspond au numero.",
      });
    }
    res.status(500).json({ error: "Erreur serveur lors de l'initialisation du paiement." });
  }
});

// ---------------------------------------------------------------------------
// 2) Webhook E-Billing (tontines) — a configurer dans le tableau de bord
//    marchand comme notification_url. Ne JAMAIS faire confiance au contenu
//    de cette requete pour marquer un paiement comme reussi : on re-interroge
//    l'etat reel via getUssdPushStatus avant d'ecrire quoi que ce soit.
// ---------------------------------------------------------------------------
app.post('/api/tontine/ebilling/notify', async (req, res) => {
  // "reference" echo notre external_reference envoye a la creation.
  const externalReference = req.body.reference;
  if (!externalReference) return res.sendStatus(400);

  if (verifyWebhookSignature(req) === false) {
    console.error(`Signature invalide sur la notification ${externalReference}.`);
    return res.sendStatus(401);
  }

  try {
    const pendingRef = db.collection('pendingOnlinePayments').doc(externalReference);
    const pendingSnap = await pendingRef.get();
    if (!pendingSnap.exists) {
      console.error(`Aucune trace pendingOnlinePayments pour ${externalReference} (deja traite ?)`);
      return res.sendStatus(200);
    }
    const pending = pendingSnap.data();

    const status = await getUssdPushStatus(pending.ussdPushId);
    if (status?.state !== 'paid') {
      console.log(`Paiement ${externalReference} non confirme comme paye (etat: ${status?.state}).`);
      return res.sendStatus(200); // on accuse reception malgre tout, sinon E-Billing reessaie indefiniment
    }

    const tontineRef = db.collection('tontines').doc(pending.tontineId);

    // Idempotence : si le webhook est livre plusieurs fois, ne pas creer
    // deux cotisations pour le meme paiement.
    const existing = await tontineRef
      .collection('contributions')
      .where('onlineTransactionId', '==', externalReference)
      .limit(1)
      .get();
    if (!existing.empty) {
      await pendingRef.delete();
      return res.sendStatus(200);
    }

    await tontineRef.collection('contributions').add({
      uid: pending.uid,
      roundIndex: pending.roundIndex,
      amount: pending.amount,
      date: admin.firestore.Timestamp.now(),
      proofImageBase64: '',
      status: 'verified', // paiement confirme par E-Billing lui-meme, pas besoin de verification humaine
      verifiedBy: 'ebilling',
      verifiedAt: admin.firestore.Timestamp.now(),
      transactionLogged: false,
      paymentMethod: 'online',
      onlineTransactionId: externalReference,
    });

    await pendingRef.delete();
    res.sendStatus(200);
  } catch (err) {
    logAxiosError('notify error:', err);
    // On repond 200 quand meme pour eviter une boucle de re-livraison sur
    // une erreur de notre cote qui ne se resoudra pas toute seule ; l'echec
    // est trace dans les logs pour investigation manuelle.
    res.sendStatus(200);
  }
});

// ---------------------------------------------------------------------------
// 3) Abonnement Premium — meme principe que les tontines : le prix vient
//    d'une table cote SERVEUR (jamais du client), et seul ce serveur (Admin
//    SDK) peut ecrire 'premium'/'premiumExpireAt' — firestore.rules
//    l'interdit explicitement au client (fieldUnchanged('premium')).
//
//    Facture en XAF (compte marchand E-Billing, base Gabon/CEMAC) — pas de
//    conversion automatique par pays pour l'instant : une vraie tarification
//    multi-devises est une decision produit a part entiere, pas traitee ici.
// ---------------------------------------------------------------------------
const PREMIUM_PLANS = {
  mensuel: { amount: 3500, days: 30 },
  annuel: { amount: 35000, days: 365 },
};

app.post('/api/premium/init-payment', requireAuth, async (req, res) => {
  try {
    const { premiumType, payerName, payerPhone, operator } = req.body;
    const uid = req.uid;
    const plan = PREMIUM_PLANS[premiumType];
    if (!plan || !payerPhone || !operator) {
      return res.status(400).json({ error: 'Parametres manquants ou plan invalide.' });
    }

    const externalReference = `pm${sanitizeForTransactionId(uid)}${premiumType}${Date.now()}`;

    const billId = await createInvoice({
      amount: plan.amount,
      payerName: payerName || 'Client',
      payerPhone,
      description: `Abonnement SmartFinance Premium (${premiumType})`,
      externalReference,
    });
    const ussdPush = await triggerUssdPush({ billId, operator, payerPhone });

    await db.collection('pendingPremiumPayments').doc(externalReference).set({
      uid,
      premiumType,
      days: plan.days,
      amount: plan.amount,
      billId,
      ussdPushId: String(ussdPush.id),
      createdAt: admin.firestore.Timestamp.now(),
    });

    res.json({ transactionId: externalReference, ussdPushId: String(ussdPush.id) });
  } catch (err) {
    logAxiosError('premium init-payment error:', err);
    if (err.response?.status === 406) {
      const detail = err.response.data || {};
      return res.status(406).json({
        error:
          detail.message ||
          detail.operator_response ||
          "Le prestataire de paiement a refuse l'operation. Verifie le format du numero " +
            "(indicatif pays sans '+' ni '0' initial, ex: 24177xxxxxxx) et que l'operateur choisi correspond au numero.",
      });
    }
    res.status(500).json({ error: "Erreur serveur lors de l'initialisation du paiement." });
  }
});

app.post('/api/premium/ebilling/notify', async (req, res) => {
  const externalReference = req.body.reference;
  if (!externalReference) return res.sendStatus(400);

  if (verifyWebhookSignature(req) === false) {
    console.error(`Signature invalide sur la notification premium ${externalReference}.`);
    return res.sendStatus(401);
  }

  try {
    const pendingRef = db.collection('pendingPremiumPayments').doc(externalReference);
    const pendingSnap = await pendingRef.get();
    if (!pendingSnap.exists) {
      console.error(`Aucune trace pendingPremiumPayments pour ${externalReference} (deja traite ?)`);
      return res.sendStatus(200);
    }
    const pending = pendingSnap.data();

    const status = await getUssdPushStatus(pending.ussdPushId);
    if (status?.state !== 'paid') {
      console.log(`Paiement premium ${externalReference} non confirme comme paye (etat: ${status?.state}).`);
      return res.sendStatus(200);
    }

    const userRef = db.collection('users').doc(pending.uid);

    // Idempotence : si E-Billing livre le webhook plusieurs fois, ne pas
    // prolonger l'abonnement une deuxieme fois pour le meme paiement. Le
    // document premiumPayments/{externalReference} sert a la fois de garde
    // d'idempotence et de signal que l'app ecoute pour confirmer le succes.
    const paymentRecordRef = userRef.collection('premiumPayments').doc(externalReference);
    const alreadyProcessed = await paymentRecordRef.get();
    if (alreadyProcessed.exists) {
      await pendingRef.delete();
      return res.sendStatus(200);
    }

    await db.runTransaction(async (tx) => {
      const userSnap = await tx.get(userRef);
      const userData = userSnap.data() || {};
      const now = admin.firestore.Timestamp.now();
      const currentExpiry = userData.premiumExpireAt;
      // Renouvellement anticipe : prolonge depuis la date d'expiration
      // actuelle si elle n'est pas encore passee, pour ne pas faire perdre
      // les jours deja payes a quelqu'un qui renouvelle en avance.
      const base =
        currentExpiry && currentExpiry.toMillis() > now.toMillis() ? currentExpiry.toDate() : now.toDate();
      const newExpiry = new Date(base.getTime() + pending.days * 24 * 60 * 60 * 1000);

      tx.update(userRef, {
        premium: true,
        premiumExpireAt: admin.firestore.Timestamp.fromDate(newExpiry),
      });
      tx.set(paymentRecordRef, {
        status: 'confirmed',
        premiumType: pending.premiumType,
        amount: pending.amount,
        confirmedAt: now,
      });
    });

    await pendingRef.delete();
    res.sendStatus(200);
  } catch (err) {
    logAxiosError('premium notify error:', err);
    res.sendStatus(200);
  }
});

// ---------------------------------------------------------------------------
// 4) Reversement au beneficiaire du tour (PAYOUT) — NON IMPLEMENTE.
//
//    La spec obtenue declare les tags "Payouts"/"Cash-in"/"KYC"/"Account"
//    mais ne liste aucun chemin pour eux — probablement des scopes non
//    encore accordes a ce compte marchand. Impossible a integrer
//    honnetement sans deviner des noms d'endpoint. En attendant, le systeme
//    existant reste disponible en parallele : chaque beneficiaire renseigne
//    ses coordonnees de reception dans l'app, et les autres participants
//    paient manuellement puis televersent une preuve (bouton "J'ai payé"),
//    verifiee par un humain.
// ---------------------------------------------------------------------------
app.post('/api/tontine/payout', requireAuth, async (_req, res) => {
  res.status(501).json({
    error:
      "Le reversement automatique n'est pas implemente. La documentation E-Billing pour les " +
      "endpoints Payout n'apparait pas encore sur ce compte marchand — recontacte Digitech " +
      "Africa pour faire activer ce scope, puis reviens completer cette route avec la vraie spec.",
  });
});

app.get('/health', (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`Serveur de paiement demarre sur le port ${PORT} (E-Billing, env=${EBILLING_ENV})`));
