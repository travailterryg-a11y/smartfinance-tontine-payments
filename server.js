// Serveur de paiement en ligne pour les tontines SmartFinance.
//
// Pourquoi un serveur separe : la cle secrete CinetPay ne doit jamais vivre
// dans l'app Flutter (n'importe qui pourrait la lire dans l'APK et falsifier
// des paiements). Firebase Cloud Functions aurait ete l'endroit naturel pour
// ca, mais necessite le plan payant Blaze. Ce serveur Node independant,
// deployable gratuitement (Render/Railway), joue le meme role : il initie le
// paiement, recoit le webhook CinetPay, RE-VERIFIE le statut aupres de
// CinetPay lui-meme (jamais confiance dans le contenu brut du webhook), puis
// ecrit dans Firestore avec les droits d'administrateur.
//
// Ce serveur ne fait PARTIE d'aucun build Flutter : c'est un projet Node
// independant, a deployer separement. Voir README.md pour le deploiement.

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const admin = require('firebase-admin');

const {
  PORT = 3000,
  CINETPAY_APIKEY,
  CINETPAY_SITE_ID,
  CINETPAY_BASE_URL = 'https://api-checkout.cinetpay.com/v2',
  PUBLIC_BACKEND_URL,
  FIREBASE_SERVICE_ACCOUNT,
  TRANSFER_ENABLED,
  CINETPAY_TRANSFER_LOGIN,
  CINETPAY_TRANSFER_PASSWORD,
} = process.env;

if (!CINETPAY_APIKEY || !CINETPAY_SITE_ID || !PUBLIC_BACKEND_URL || !FIREBASE_SERVICE_ACCOUNT) {
  console.error(
    'Variables d\'environnement manquantes. Copie .env.example en .env et remplis-le ' +
      '(voir README.md).'
  );
  process.exit(1);
}

admin.initializeApp({
  credential: admin.credential.cert(JSON.parse(FIREBASE_SERVICE_ACCOUNT)),
});
const db = admin.firestore();

const app = express();
app.use(cors());
app.use(express.json());

// Verifie le jeton Firebase envoye par l'app (header "Authorization: Bearer
// <idToken>") et attache l'uid VERIFIE a req.uid. Avant ce middleware,
// init-payment faisait confiance a un champ "uid" envoye tel quel dans le
// corps de la requete : n'importe qui pouvait donc initier un paiement en
// se faisant passer pour un autre participant (le paiement reel arriverait
// bien, mais la cotisation serait attribuee a la mauvaise personne, lui
// permettant de "sauter" son tour sans jamais payer).
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

// Devises acceptees par CinetPay (zone UEMOA/CEMAC principalement). Le
// modele "currencySymbol" cote app est un texte libre (ex: "FCFA") -> on le
// fait correspondre au code ISO attendu par CinetPay. Ajuste cette table si
// tes utilisateurs sont dans une devise non listee ici.
function toCinetpayCurrency(currencySymbol) {
  const map = {
    FCFA: 'XOF',
    XOF: 'XOF',
    XAF: 'XAF',
    CDF: 'CDF',
    GNF: 'GNF',
    USD: 'USD',
    EUR: 'EUR',
  };
  return map[(currencySymbol || '').toUpperCase()] || 'XOF';
}

function sanitizeForTransactionId(value) {
  return String(value).replace(/[^a-zA-Z0-9]/g, '').slice(0, 20);
}

// ---------------------------------------------------------------------------
// 1) Initier un paiement : l'app appelle cette route quand le participant
//    tape "Payer en ligne". Le montant vient de la tontine cote SERVEUR
//    (jamais du client) pour qu'un client modifie ne puisse pas payer moins
//    que sa cotisation reelle.
// ---------------------------------------------------------------------------
app.post('/api/tontine/init-payment', requireAuth, async (req, res) => {
  try {
    const { tontineId, roundIndex, payerName, payerPhone } = req.body;
    const uid = req.uid; // jamais depuis req.body : voir requireAuth ci-dessus.
    if (!tontineId || roundIndex === undefined || !payerPhone) {
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
    const currency = toCinetpayCurrency(tontine.currencySymbol);
    const transactionId = `tt${sanitizeForTransactionId(tontineId)}r${roundIndex}${sanitizeForTransactionId(
      uid
    )}${Date.now()}`;

    const payload = {
      apikey: CINETPAY_APIKEY,
      site_id: CINETPAY_SITE_ID,
      transaction_id: transactionId,
      amount,
      currency,
      description: `Cotisation tontine ${tontine.name} - tour ${Number(roundIndex) + 1}`,
      notify_url: `${PUBLIC_BACKEND_URL}/api/tontine/cinetpay/notify`,
      return_url: `${PUBLIC_BACKEND_URL}/api/tontine/return`,
      channels: 'ALL',
      customer_name: payerName || 'Participant',
      customer_surname: 'SmartFinance',
      customer_phone_number: payerPhone,
    };

    const cinetpayRes = await axios.post(`${CINETPAY_BASE_URL}/payment`, payload);
    const data = cinetpayRes.data;

    if (data.code !== '201') {
      console.error('CinetPay init refuse :', data);
      return res.status(502).json({ error: "CinetPay a refuse l'initialisation.", detail: data.message });
    }

    // Trace en attente (collection racine, cle = transaction_id) pour que le
    // webhook puisse retrouver directement la tontine/le tour/le montant
    // sans avoir a les re-deviner depuis le texte du transaction_id.
    await db.collection('pendingOnlinePayments').doc(transactionId).set({
      tontineId,
      uid,
      roundIndex: Number(roundIndex),
      amount,
      currency,
      createdAt: admin.firestore.Timestamp.now(),
    });

    res.json({ paymentUrl: data.data.payment_url, transactionId });
  } catch (err) {
    console.error('init-payment error:', err.response?.data || err.message);
    res.status(500).json({ error: "Erreur serveur lors de l'initialisation du paiement." });
  }
});

// ---------------------------------------------------------------------------
// 2) Webhook CinetPay : ne JAMAIS faire confiance au contenu de cette
//    requete pour marquer un paiement comme reussi. On re-interroge
//    CinetPay avec la cle secrete (cote serveur uniquement) pour confirmer
//    le statut reel avant d'ecrire quoi que ce soit.
// ---------------------------------------------------------------------------
app.post('/api/tontine/cinetpay/notify', async (req, res) => {
  const transactionId = req.body.cpm_trans_id || req.body.transaction_id;
  if (!transactionId) return res.sendStatus(400);

  try {
    const checkRes = await axios.post(`${CINETPAY_BASE_URL}/payment/check`, {
      apikey: CINETPAY_APIKEY,
      site_id: CINETPAY_SITE_ID,
      transaction_id: transactionId,
    });
    const result = checkRes.data;

    if (result.code !== '00' || result.data?.status !== 'ACCEPTED') {
      console.log(`Paiement ${transactionId} non accepte (statut: ${result.data?.status}).`);
      return res.sendStatus(200); // on accuse reception malgre tout, sinon CinetPay reessaie indefiniment
    }

    // Retrouver la trace laissee a l'initialisation pour savoir a quelle
    // tontine/tour/participant ce paiement correspond.
    const pendingRef = db.collection('pendingOnlinePayments').doc(transactionId);
    const pendingSnap = await pendingRef.get();
    if (!pendingSnap.exists) {
      console.error(`Aucune trace pendingOnlinePayments pour ${transactionId} (deja traite ?)`);
      return res.sendStatus(200);
    }
    const pending = pendingSnap.data();
    const tontineRef = db.collection('tontines').doc(pending.tontineId);

    // Idempotence : si le webhook est livre plusieurs fois par CinetPay, ne
    // pas creer deux cotisations pour le meme paiement.
    const existing = await tontineRef
      .collection('contributions')
      .where('onlineTransactionId', '==', transactionId)
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
      status: 'verified', // paiement confirme par CinetPay lui-meme, pas besoin de verification humaine
      verifiedBy: 'cinetpay',
      verifiedAt: admin.firestore.Timestamp.now(),
      transactionLogged: false,
      paymentMethod: 'online',
      onlineTransactionId: transactionId,
    });

    await pendingRef.delete();

    res.sendStatus(200);
  } catch (err) {
    console.error('notify error:', err.response?.data || err.message);
    // On repond 200 quand meme pour eviter une boucle de re-livraison sur
    // une erreur de notre cote qui ne se resoudra pas toute seule ; l'echec
    // est trace dans les logs pour investigation manuelle.
    res.sendStatus(200);
  }
});

// Page affichee dans la WebView apres le paiement (CinetPay redirige ici).
// L'app Flutter detecte la navigation vers /api/tontine/return et ferme la
// WebView elle-meme ; cette page n'est qu'un filet de securite si jamais
// l'utilisateur la voit quelques instants.
app.get('/api/tontine/return', (req, res) => {
  res.send(`<!doctype html><html><head><meta charset="utf-8">
    <title>Paiement en cours de confirmation</title></head>
    <body style="font-family: sans-serif; text-align:center; padding-top:60px;">
      <h2>Paiement recu</h2>
      <p>Tu peux retourner sur l'application SmartFinance.</p>
    </body></html>`);
});

// ---------------------------------------------------------------------------
// 3) Reversement au beneficiaire du tour. DESACTIVE PAR DEFAUT.
//
//    Contrairement au paiement (bien documente et stable chez CinetPay),
//    l'API de transfert d'argent CinetPay necessite une activation
//    contractuelle separee (KYC) et ses parametres exacts doivent etre
//    verifies aupres du support CinetPay / du tableau de bord au moment de
//    l'activation - ne pas activer TRANSFER_ENABLED sans avoir valide ces
//    details avec CinetPay au prealable.
// ---------------------------------------------------------------------------
app.post('/api/tontine/payout', requireAuth, async (req, res) => {
  if (TRANSFER_ENABLED !== 'true') {
    return res.status(503).json({
      error:
        "Le reversement automatique n'est pas active. Active la fonctionnalite " +
        '"Transfert d\'argent" sur ton compte CinetPay (KYC requis), puis passe ' +
        'TRANSFER_ENABLED=true et renseigne CINETPAY_TRANSFER_LOGIN/PASSWORD.',
    });
  }

  try {
    const { tontineId, roundIndex } = req.body;
    if (!tontineId || roundIndex === undefined) {
      return res.status(400).json({ error: 'Parametres manquants.' });
    }
    const tontineSnap = await db.collection('tontines').doc(tontineId).get();
    if (!tontineSnap.exists) return res.status(404).json({ error: 'Tontine introuvable.' });
    const tontine = tontineSnap.data();

    // Reserve au createur : un virement reel ne doit jamais pouvoir etre
    // declenche par n'importe qui connaissant/devinant un tontineId.
    if (tontine.creatorUid !== req.uid) {
      return res.status(403).json({ error: "Seul le createur de la tontine peut declencher un reversement." });
    }

    const recipientUid = tontine.rotationOrder[roundIndex % tontine.rotationOrder.length];
    const recipientInfo = tontine.participantPaymentInfo?.[recipientUid];
    if (!recipientInfo || !recipientInfo.accountNumber) {
      return res.status(400).json({ error: "Le beneficiaire n'a pas renseigne ses informations de reception." });
    }

    // Le tour doit etre complet (chaque participant a une cotisation
    // verifiee pour ce tour precis) avant tout reversement — meme regle que
    // TontineRotationCalculator.isRoundComplete cote app, pour ne jamais
    // reverser un pot partiel.
    const verifiedSnap = await db
      .collection('tontines')
      .doc(tontineId)
      .collection('contributions')
      .where('roundIndex', '==', roundIndex)
      .where('status', '==', 'verified')
      .get();
    const contributorUids = new Set(verifiedSnap.docs.map((d) => d.data().uid));
    const participantUids = Array.isArray(tontine.participantUids) ? tontine.participantUids : [];
    const roundComplete = participantUids.length > 0 && participantUids.every((u) => contributorUids.has(u));
    if (!roundComplete) {
      return res.status(400).json({ error: "Tous les participants n'ont pas encore une cotisation verifiee pour ce tour." });
    }

    // Garde anti-double-reversement : un document de verrou par tour, cree
    // de facon atomique. Si le tour a deja ete reverse (ou est en cours de
    // traitement par un appel concurrent), on refuse plutot que d'envoyer un
    // deuxieme virement pour le meme pot.
    const payoutLockRef = db.collection('tontines').doc(tontineId).collection('payouts').doc(String(roundIndex));
    try {
      await db.runTransaction(async (tx) => {
        const existing = await tx.get(payoutLockRef);
        if (existing.exists) {
          throw new Error('ALREADY_PAID_OUT');
        }
        tx.set(payoutLockRef, {
          status: 'processing',
          triggeredBy: req.uid,
          createdAt: admin.firestore.Timestamp.now(),
        });
      });
    } catch (lockErr) {
      if (lockErr.message === 'ALREADY_PAID_OUT') {
        return res.status(409).json({ error: 'Ce tour a deja ete reverse (ou est en cours de traitement).' });
      }
      throw lockErr;
    }

    // A partir d'ici le verrou est pose : toute sortie en erreur doit le
    // liberer (delete) plutot que le laisser bloque a "processing" pour
    // toujours, sinon un echec transitoire (reseau, CinetPay indisponible)
    // empecherait definitivement de reessayer ce tour.
    try {
      // Authentification CinetPay Transfert (jeton separe de l'API de paiement).
      const authRes = await axios.post('https://client.cinetpay.com/v1/auth/login', {
        apikey: CINETPAY_APIKEY,
        password: CINETPAY_TRANSFER_PASSWORD,
      });
      const token = authRes.data?.data?.token;
      if (!token) {
        await payoutLockRef.delete();
        return res.status(502).json({ error: "Authentification CinetPay Transfert echouee." });
      }

      const verifiedCount = verifiedSnap.size;
      const totalAmount = Math.round(Number(tontine.contributionAmount) * verifiedCount);

      const transferRes = await axios.post(
        `https://client.cinetpay.com/v1/transfer/money/send/contact?token=${token}`,
        {
          prefix: '',
          phone: recipientInfo.accountNumber,
          amount: totalAmount,
          notify_url: `${PUBLIC_BACKEND_URL}/api/tontine/transfer-notify`,
          client_transaction_id: `payout_${sanitizeForTransactionId(tontineId)}_${roundIndex}_${Date.now()}`,
        }
      );

      await payoutLockRef.set(
        { status: 'done', amount: totalAmount, doneAt: admin.firestore.Timestamp.now() },
        { merge: true }
      );

      res.json({ ok: true, detail: transferRes.data });
    } catch (transferErr) {
      await payoutLockRef.delete();
      throw transferErr;
    }
  } catch (err) {
    console.error('payout error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Erreur lors du reversement.' });
  }
});

app.get('/health', (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log(`Serveur de paiement tontine demarre sur le port ${PORT}`));
