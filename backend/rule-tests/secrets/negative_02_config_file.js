// Test: negative for rule SEC-002
// Expected: should_not_trigger
// Category: secrets
// Language: javascript

/**
 * Payment and notification service configuration.
 * All API keys are loaded from environment variables at startup.
 */

const axios = require('axios');
const Stripe = require('stripe');

function loadConfig() {
  const required = ['STRIPE_SECRET_KEY', 'STRIPE_WEBHOOK_SECRET', 'SENDGRID_API_KEY'];
  const missing = required.filter((key) => !process.env[key]);
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
  }

  return {
    stripe: {
      secretKey: process.env.STRIPE_SECRET_KEY,
      webhookSecret: process.env.STRIPE_WEBHOOK_SECRET,
    },
    sendgrid: {
      apiKey: process.env.SENDGRID_API_KEY,
      fromAddress: process.env.SENDGRID_FROM || 'noreply@example.com',
    },
  };
}

const config = loadConfig();
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
