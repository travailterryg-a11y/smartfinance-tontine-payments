# Serveur de paiement en ligne — Tontines SmartFinance

Petit serveur Node.js independant (PAS un module Flutter) qui gere le
paiement en ligne des cotisations de tontine via CinetPay. Il existe parce
que la cle secrete CinetPay ne doit jamais etre integree dans l'app mobile,
et que Firebase Cloud Functions (l'alternative naturelle) exige le plan
payant Blaze.

## Ce qu'il fait

1. **Initier un paiement** (`POST /api/tontine/init-payment`) : l'app appelle
   cette route quand un participant clique "Payer en ligne". Le serveur va
   lire le montant reel de la cotisation directement dans Firestore (jamais
   depuis l'app, pour eviter qu'un client modifie ne triche sur le montant),
   puis demande a CinetPay une page de paiement et renvoie son URL a l'app.
2. **Webhook CinetPay** (`POST /api/tontine/cinetpay/notify`) : CinetPay
   appelle cette route quand un paiement est termine. Le serveur ne fait
   JAMAIS confiance a ce contenu brut : il rappelle l'API `payment/check` de
   CinetPay avec la cle secrete pour confirmer le statut reel, puis cree la
   cotisation dans Firestore avec le statut `verified` (le paiement est deja
   confirme par CinetPay, pas besoin de verification humaine).
3. **Reversement au beneficiaire** (`POST /api/tontine/payout`) : DESACTIVE
   par defaut (`TRANSFER_ENABLED=false`). Necessite d'avoir active la
   fonctionnalite "Transfert d'argent" sur ton compte CinetPay (KYC separe).

## Ce que tu dois faire toi-meme (je ne peux pas le faire a ta place)

### 1. Compte CinetPay
- Cree un compte marchand sur https://cinetpay.com (choisis le pays/la zone
  ou vivent tes utilisateurs).
- Dans le tableau de bord : Integration > recupere `APIKEY` et `SITE_ID`.
- Active les moyens de paiement mobile money que tu veux accepter (Orange
  Money, MTN, Moov, Wave...).

### 2. Compte de service Firebase
- Console Firebase > Parametres du projet > Comptes de service > "Generer
  une nouvelle cle privee" (bouton en bas). Un fichier JSON se telecharge.
- Tu n'as PAS besoin du plan Blaze pour ca : le compte de service et l'Admin
  SDK sont disponibles sur le plan gratuit Spark, seuls Cloud Functions et
  Storage l'exigent.
- Ouvre ce fichier JSON, copie tout son contenu, colle-le comme valeur de
  `FIREBASE_SERVICE_ACCOUNT` dans ton `.env` (tout sur une seule ligne).

### 3. Deploiement gratuit (Render, recommande)
1. Cree un compte sur https://render.com.
2. "New +" > "Web Service" > connecte ce depot (ou pousse juste le dossier
   `payment_backend/` dans un depot Git separe).
3. Render detecte Node automatiquement. Renseigne :
   - Build command : `npm install`
   - Start command : `npm start`
4. Dans l'onglet "Environment", ajoute toutes les variables de
   `.env.example` avec tes vraies valeurs.
5. Une fois deploye, Render te donne une URL du type
   `https://smartfinance-pay.onrender.com` — mets cette URL dans
   `PUBLIC_BACKEND_URL` (redeploie apres l'avoir ajoutee), et donne-la a
   l'app Flutter via `--dart-define=PAYMENT_BACKEND_URL=https://smartfinance-pay.onrender.com`.

Note sur le plan gratuit Render : le service se met en veille apres 15 min
d'inactivite et met quelques secondes a se reveiller au premier appel — sans
consequence ici puisque l'app attend deja la confirmation via Firestore.

### 4. Test local (optionnel avant de deployer)
```bash
cd payment_backend
npm install
cp .env.example .env
# remplis .env avec tes vraies valeurs
npm start
```
Pour que CinetPay puisse t'atteindre en local, utilise un tunnel (ex.
`ngrok http 3000`) et mets l'URL ngrok dans `PUBLIC_BACKEND_URL`.

## Securite — ce qui est deja fait

- La cle secrete CinetPay ne quitte jamais ce serveur.
- Le webhook re-verifie chaque paiement aupres de CinetPay avant d'ecrire
  quoi que ce soit (protection contre un faux appel webhook forge par un
  tiers).
- Le montant de la cotisation est lu depuis Firestore cote serveur, jamais
  envoye par l'app (protection contre un client modifie qui tenterait de
  payer un montant inferieur).
- Idempotence : un meme paiement confirme deux fois par CinetPay (retries)
  ne cree jamais deux cotisations.

## Hors scope pour l'instant

Le reversement automatique (`/api/tontine/payout`) utilise l'API "Transfert
d'argent" de CinetPay, moins standard que l'encaissement et dont les
parametres exacts dependent du contrat active sur ton compte — verifie-les
avec le support CinetPay avant de passer `TRANSFER_ENABLED=true`. En
attendant, le systeme existant reste disponible en parallele : chaque
beneficiaire renseigne ses coordonnees de reception dans l'app, et les
autres participants peuvent toujours payer manuellement puis televerser une
preuve (bouton "J'ai payé").
