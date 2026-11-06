// The Deception Gallery cases the Explorer offers as one-click inputs. `mock` names the contract example
// used when the API is down. Each case is investigated live by the real brain when the API is up.
import type { Source } from "./types";

export interface Case {
  id: string;
  title: string;
  raw: string;
  source: Source;
  mock?: string;
  input: { src: string; msg: string; ctx: string };
}

export const GALLERY: Case[] = [
  { id: "01", title: "The invisible letter", raw: "https://pаytm.com/login", source: "gallery", mock: "01-invisible-letter",
    input: { src: "💬 SMS received", msg: "Your Paytm KYC expires today. Re-verify now to keep your wallet active:",
             ctx: "In a phone font the Russian “а” is pixel-identical to an English “a”." } },
  { id: "02", title: "The twin letters", raw: "paytrn.com", source: "gallery", mock: "02-twin-letters",
    input: { src: "💬 WhatsApp forward", msg: "₹500 cashback credited to your wallet! Claim on Paytm:",
             ctx: "At 16 px, “rn” reads as “m”. Letter counting calls it only “medium close”." } },
  { id: "03", title: "Registered today", raw: "sbi-kyc-update.in", source: "nrd_snapshot", mock: "03-sleeper-combosquat",
    input: { src: "🗂️ New-domain list", msg: "No website yet.",
             ctx: "A screenshot tool would say “safe”: there's nothing to see." } },
  { id: "04", title: "The disguise", raw: "https://echallan.parivahan.gov.in.pay-fine.icu/challan", source: "gallery",
    mock: "04-subdomain-disguise",
    input: { src: "💬 SMS received", msg: "Traffic e-Challan of ₹2,000 pending. Pay today to avoid court action:",
             ctx: "The message shows the real gov.in address first; the real owner hides at the end." } },
  { id: "05", title: "Random name, copied page", raw: "https://kx72-secure.top/", source: "gallery", mock: "05-brandless-clone",
    input: { src: "📡 Certificate feed", msg: "A random-looking new HTTPS site.",
             ctx: "No brand in the name, so name-only tools stop here." } },
  { id: "06", title: "Odd-looking real bank", raw: "https://onlinesbi.sbi.bank.in/", source: "gallery", mock: "06-genuine-weirdo",
    input: { src: "🗂️ New-domain list", msg: "Four parts, two “sbi”s. Looks strange.",
             ctx: "A naive “flag anything odd” rule would block India's largest bank." } },
  { id: "07", title: "Brand inside a word", raw: "thanksbitcoin.com", source: "nrd_snapshot", mock: "07-benign-substring",
    input: { src: "🗂️ New-domain list", msg: "Contains the letters “sbi”.",
             ctx: "Substring matchers flag it. The brand only appears inside other words." } },
  { id: "08", title: "The trust-signal fake", raw: "sbi.bank-in.com", source: "gallery",
    input: { src: "💬 SMS received", msg: "As per RBI, banks now use bank.in. Verify your SBI account here:",
             ctx: "People were told “banks end in .bank.in”, so the attacker wrote “bank-in”." } },
  { id: "09", title: "The late mover", raw: "sbi.co.in", source: "gallery",
    input: { src: "🧾 Analyst check", msg: "RBI asked banks to move to .bank.in by 31 Oct 2025.",
             ctx: "Old addresses still run during the move. Is this one fake now?" } },
];

export const SOURCE_STORY: Partial<Record<Source, string>> = {
  paste: "📋 Pasted by the analyst", api: "🔌 API call", fool_it: "🎯 Try to fool it", file: "🗂️ Batch file",
  stdin: "🗂️ Batch (stdin)", nrd_snapshot: "🗂️ New-domain list", ct_feed: "📡 Certificate feed", gallery: "🖼️ Gallery",
};

/** For the batch view: the gallery, real e-Challan-campaign names from the NRD hand check
 *  (docs/eval/p5-nrd-handcheck.md, names only), brand affiliates, and ordinary new sites. */
export const BATCH_SAMPLE = `# Doppel batch sample: names only, nothing is opened
paytrn.com
xn--pytm-53d.com
sbi-kyc-update.in
echallan.parivahan.gov.in.pay-fine.icu
kx72-secure.top
onlinesbi.sbi.bank.in
thanksbitcoin.com
sbi.bank-in.com
sbi.co.in
in-echallan.online
in-echallan.party
ln-echallan.bid
sbi-yono-rewardz.in
hdfcbank-kyc-update.com
icici-netbanking-login.top
indiapost-parcel-hold.icu
incometax-refund-status.in
g00gle-account-verify.com
blog.google
icicilombard.com
hdfcbank.bank.in
sbi-kyc.web.app
chai-and-code.in
mumbai-bakery-orders.in
`;
