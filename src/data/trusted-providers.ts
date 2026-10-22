export interface TrustedProvider {
  domain: string;
  label: string;
  kind: "identity" | "payment" | "platform";
}

/**
 * Cross-origin form destinations that are common and legitimate. Presence here
 * means "requires verification, not automatically malicious" — never proof of
 * safety, because a provider's page could itself be abused or imitated.
 */
export const TRUSTED_PROVIDERS: TrustedProvider[] = [
  { domain: "paypal.com", label: "PayPal", kind: "payment" },
  { domain: "stripe.com", label: "Stripe", kind: "payment" },
  { domain: "checkout.stripe.com", label: "Stripe Checkout", kind: "payment" },
  { domain: "squareup.com", label: "Square", kind: "payment" },
  { domain: "square.com", label: "Square", kind: "payment" },
  { domain: "authorize.net", label: "Authorize.net", kind: "payment" },
  { domain: "adyen.com", label: "Adyen", kind: "payment" },
  { domain: "braintreegateway.com", label: "Braintree", kind: "payment" },
  { domain: "klarna.com", label: "Klarna", kind: "payment" },
  { domain: "affirm.com", label: "Affirm", kind: "payment" },
  { domain: "afterpay.com", label: "Afterpay", kind: "payment" },
  { domain: "worldpay.com", label: "Worldpay", kind: "payment" },
  { domain: "amazon.com", label: "Amazon Pay", kind: "payment" },
  { domain: "plaid.com", label: "Plaid", kind: "platform" },
  { domain: "accounts.google.com", label: "Google Sign-In", kind: "identity" },
  { domain: "appleid.apple.com", label: "Sign in with Apple", kind: "identity" },
  { domain: "login.microsoftonline.com", label: "Microsoft Sign-In", kind: "identity" },
  { domain: "login.live.com", label: "Microsoft Sign-In", kind: "identity" },
  { domain: "okta.com", label: "Okta", kind: "identity" },
  { domain: "auth0.com", label: "Auth0", kind: "identity" },
  { domain: "onelogin.com", label: "OneLogin", kind: "identity" },
  { domain: "duosecurity.com", label: "Duo", kind: "identity" },
  { domain: "salesforce.com", label: "Salesforce", kind: "platform" },
  { domain: "shopify.com", label: "Shopify", kind: "platform" },
  { domain: "facebook.com", label: "Facebook Login", kind: "identity" },
  { domain: "github.com", label: "GitHub", kind: "identity" },
  { domain: "amazoncognito.com", label: "Amazon Cognito", kind: "identity" },
  { domain: "pingidentity.com", label: "Ping Identity", kind: "identity" },
];

export function findTrustedProvider(hostname: string): TrustedProvider | null {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  return (
    TRUSTED_PROVIDERS.find(
      (provider) => host === provider.domain || host.endsWith(`.${provider.domain}`),
    ) ?? null
  );
}
