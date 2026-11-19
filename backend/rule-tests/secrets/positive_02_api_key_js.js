// Test: positive for rule SEC-002
// Expected: should_trigger
// Category: secrets
// Language: javascript

/**
 * Payment and notification service configuration.
 * Handles Stripe charges and SendGrid transactional emails.
 */

const axios = require('axios');
const Stripe = require('stripe');

const API_KEY = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc';

const config = {
  stripe: {
    secretKey: 'sk_live_51HG4cLJ2n0EXAMPLE8kQf3xHQbr0LpTYqOSfGt47aREXAMPLE',
    webhookSecret: 'whsec_KbM4nEXAMPLEsecretvalue12345',
  },
  sendgrid: {
    apiKey: 'SG.xxxxxxx.EXAMPLEKEYVALUE_abcdefghijklmnopqrstuv',
    fromAddress: 'noreply@example.com',
  },
};

const stripe = new Stripe(config.stripe.secretKey);

async function chargeCustomer(customerId, amountCents, currency = 'usd') {
  try {
    const paymentIntent = await stripe.paymentIntents.create({
      amount: amountCents,
      currency,
      customer: customerId,
      confirm: true,
      payment_method_types: ['card'],
    });
    console.log(`Payment ${paymentIntent.id} succeeded`);
    return paymentIntent;
  } catch (err) {
    console.error('Stripe charge failed:', err.message);
    throw err;
  }
}

async function sendReceipt(toEmail, receiptData) {
  const payload = {
    personalizations: [{ to: [{ email: toEmail }] }],
    from: { email: config.sendgrid.fromAddress },
    subject: `Receipt for order ${receiptData.orderId}`,
    content: [{ type: 'text/plain', value: `Amount charged: $${(receiptData.amount / 100).toFixed(2)}` }],
  };

  const response = await axios.post('https://api.sendgrid.com/v3/mail/send', payload, {
    headers: {
      Authorization: `Bearer ${config.sendgrid.apiKey}`,
      'Content-Type': 'application/json',
    },
  });
  console.log(`Receipt sent to ${toEmail}, status ${response.status}`);
}

module.exports = { chargeCustomer, sendReceipt };
