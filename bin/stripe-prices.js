#!/usr/bin/env node
/*
 * hiccup — bin/stripe-prices.js
 *
 * One-shot setup: make sure the Stripe products and prices the pricing page
 * sells actually exist, and record their ids in data/config.json.
 *
 * Run it as:
 *
 *     STRIPE_SECRET_KEY=sk_live_... node bin/stripe-prices.js
 *
 * The key is read from the environment and never written anywhere — price ids
 * are public identifiers that show up in checkout URLs, so those go in
 * config.json, but the key stays where you put it.
 *
 * SAFE TO RE-RUN. Everything here is matched before it is created: a product is
 * found by its metadata, a price by its exact currency/amount/interval on that
 * product. Running it twice makes no second product and no second price, which
 * matters because Stripe prices are immutable and cannot be tidied up
 * afterwards — you can only deactivate them.
 *
 * It also never touches the Team prices that are already live. Those were made
 * by hand in the dashboard and are attached to real subscriptions; this only
 * fills in whatever is MISSING from config.json.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const stripe = require('../lib/stripe');

const DATA_DIR = process.env.HICCUP_DATA_DIR || path.join(__dirname, '..', 'data');
const CONFIG_FILE = path.join(DATA_DIR, 'config.json');

// What the pricing page promises. Amounts are in cents and TAX-INCLUSIVE:
// Stripe Managed Payments is the merchant of record for hiccup and settles the
// VAT out of the amount charged, so €10 is what the customer pays, not what
// hiccup nets.
const CATALOGUE = [
  {
    tier: 'pro',
    product: {
      name: 'hiccup Pro',
      description: 'Individual plan — captures up to 250 MB and priority in the analysis queue.',
    },
    prices: [
      { key: 'stripeProPriceMonthly', amount: 1000, interval: 'month', label: '€10 / month' },
      { key: 'stripeProPriceAnnual', amount: 10000, interval: 'year', label: '€100 / year' },
    ],
  },
];

const CURRENCY = 'eur';

function readConfig() {
  try {
    const parsed = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
    throw new Error('config.json is not an object');
  } catch (e) {
    if (e.code === 'ENOENT') return {};
    throw e;
  }
}

/**
 * Write config.json back, keeping a timestamped copy of what was there.
 *
 * The backup is not paranoia for its own sake: this file can hold the Stripe
 * webhook secret on deployments that have not moved it into the service
 * environment, and losing that means every webhook fails signature checks with
 * no obvious cause.
 */
function writeConfig(cfg, stamp) {
  if (fs.existsSync(CONFIG_FILE)) {
    const backup = CONFIG_FILE + '.' + stamp + '.bak';
    fs.copyFileSync(CONFIG_FILE, backup);
    console.log('  backed up config.json -> ' + path.basename(backup));
  }
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2) + '\n');
}

/** Find the product this tier uses, by the metadata we stamp on it. */
async function findProduct(tier) {
  // Listing and filtering rather than the search API: search is eventually
  // consistent and can miss a product created seconds ago, which is exactly the
  // case that would make a re-run duplicate one.
  let startingAfter = null;
  for (let page = 0; page < 10; page++) {
    const qs = ['limit=100', 'active=true'];
    if (startingAfter) qs.push('starting_after=' + encodeURIComponent(startingAfter));
    const res = await stripe._api('GET', '/v1/products?' + qs.join('&'));
    const items = (res && res.data) || [];
    for (const p of items) {
      if (p && p.metadata && p.metadata.hiccup_tier === tier) return p;
    }
    if (!res || !res.has_more || !items.length) return null;
    startingAfter = items[items.length - 1].id;
  }
  return null;
}

/** An existing active price on `productId` matching exactly what we want. */
async function findPrice(productId, amount, interval) {
  let startingAfter = null;
  for (let page = 0; page < 10; page++) {
    const qs = ['limit=100', 'active=true', 'product=' + encodeURIComponent(productId)];
    if (startingAfter) qs.push('starting_after=' + encodeURIComponent(startingAfter));
    const res = await stripe._api('GET', '/v1/prices?' + qs.join('&'));
    const items = (res && res.data) || [];
    for (const p of items) {
      if (!p || !p.recurring) continue;
      if (p.currency !== CURRENCY) continue;
      if (p.unit_amount !== amount) continue;
      if (p.recurring.interval !== interval) continue;
      if (p.recurring.interval_count !== 1) continue;
      return p;
    }
    if (!res || !res.has_more || !items.length) return null;
    startingAfter = items[items.length - 1].id;
  }
  return null;
}

async function main() {
  const cfg = readConfig();
  stripe.initStripe(cfg);

  if (!process.env.STRIPE_SECRET_KEY && !cfg.stripeSecretKey) {
    console.error('No Stripe secret key.\n');
    console.error('Run it with the key in the environment, e.g. in PowerShell:');
    console.error('  $env:STRIPE_SECRET_KEY = "sk_live_..."; node bin/stripe-prices.js\n');
    process.exit(2);
  }

  const live = stripe.isLiveMode();
  console.log('');
  console.log('  Stripe mode: ' + (live ? 'LIVE — real money' : 'TEST'));
  console.log('  Config file: ' + CONFIG_FILE);
  console.log('');

  let changed = false;

  for (const entry of CATALOGUE) {
    let product = await findProduct(entry.tier);
    if (product) {
      console.log('  product "' + product.name + '" already exists (' + product.id + ')');
    } else {
      product = await stripe._api('POST', '/v1/products', {
        name: entry.product.name,
        description: entry.product.description,
        metadata: { hiccup_tier: entry.tier },
      });
      console.log('  CREATED product "' + product.name + '" (' + product.id + ')');
    }

    for (const want of entry.prices) {
      if (cfg[want.key]) {
        console.log('  ' + want.key + ' already set in config (' + cfg[want.key] + ') — left alone');
        continue;
      }
      let price = await findPrice(product.id, want.amount, want.interval);
      if (price) {
        console.log('  found existing price ' + want.label + ' (' + price.id + ')');
      } else {
        price = await stripe._api('POST', '/v1/prices', {
          product: product.id,
          currency: CURRENCY,
          unit_amount: want.amount,
          // Managed Payments settles VAT out of this amount rather than adding
          // to it, so the figure on the pricing page is the figure charged.
          tax_behavior: 'inclusive',
          recurring: { interval: want.interval, interval_count: 1 },
          metadata: { hiccup_tier: entry.tier, hiccup_launch: 'true' },
        });
        console.log('  CREATED price ' + want.label + ' (' + price.id + ')');
      }
      cfg[want.key] = price.id;
      changed = true;
    }
  }

  console.log('');
  if (changed) {
    // A readable stamp rather than Date.now(), because these get read by a
    // human staring at a directory of .bak files. Kept to millisecond
    // resolution: two runs in the same second are exactly what happens when
    // someone re-runs this after a typo, and second resolution silently
    // overwrites the backup from the first one.
    const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 23);
    writeConfig(cfg, stamp);
    console.log('  config.json updated.');
    console.log('');
    console.log('  Restart hiccup for it to take effect:');
    console.log('    Restart-Service hiccup -Force        (elevated)');
  } else {
    console.log('  Nothing to do — every price was already configured.');
  }
  console.log('');
}

main().catch((e) => {
  console.error('');
  console.error('  FAILED: ' + (e && e.message ? e.message : e));
  console.error('');
  console.error('  Nothing was written to config.json. Stripe may still have');
  console.error('  created a product or price before the failure — re-running is');
  console.error('  safe, it will find and reuse anything that already exists.');
  console.error('');
  process.exit(1);
});
