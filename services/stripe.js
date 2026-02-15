const Stripe = require('stripe');

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);

const PLANS = {
  pro: {
    name: 'TubeScore Pro',
    description: 'Unlimited video scans per month',
    amount: 1200,
  },
  agency: {
    name: 'TubeScore Agency',
    description: 'Unlimited scans + competitor analysis + multi-channel support',
    amount: 2900,
  },
};

async function createCheckoutSession(origin, plan, opts = {}) {
  const selected = PLANS[plan] || PLANS.pro;

  const params = {
    mode: 'subscription',
    payment_method_types: ['card'],
    line_items: [
      {
        price_data: {
          currency: 'usd',
          product_data: {
            name: selected.name,
            description: selected.description,
          },
          unit_amount: selected.amount,
          recurring: { interval: 'month' },
        },
        quantity: 1,
      },
    ],
    success_url: `${origin}/?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${origin}/`,
  };

  if (opts.customer) params.customer = opts.customer;
  else if (opts.customer_email) params.customer_email = opts.customer_email;
  if (opts.metadata) params.metadata = opts.metadata;

  const session = await stripe.checkout.sessions.create(params);
  return session;
}

async function verifyProStatus(sessionId) {
  try {
    const session = await stripe.checkout.sessions.retrieve(sessionId);
    const amount = session.amount_total;
    let plan = 'pro';
    if (amount >= 2900) plan = 'agency';

    return {
      isPro: session.payment_status === 'paid',
      plan,
      customerId: session.customer,
      subscriptionId: session.subscription,
      email: session.customer_details?.email,
    };
  } catch {
    return { isPro: false };
  }
}

async function createBillingPortalSession(customerId, returnUrl) {
  const session = await stripe.billingPortal.sessions.create({
    customer: customerId,
    return_url: returnUrl,
  });
  return session;
}

module.exports = { stripe, createCheckoutSession, verifyProStatus, createBillingPortalSession };
