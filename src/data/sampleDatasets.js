/**
 * Realistic, clearly synthetic sample datasets for testing & live demo.
 * Includes valid PII entities alongside deliberate decoy numbers (invalid Luhn,
 * software version numbers, and non-UIDAI 0/1-prefixed 12-digit IDs).
 */

export const SAMPLE_DATASETS = [
  {
    id: 'it-server-log',
    label: 'IT Server Log & Ticket',
    shortLabel: 'Server Log',
    extension: 'txt',
    description:
      'Recurring emails, IPv4/IPv6 trails, intl phones, valid Visa/Mastercard, plus invalid 16-digit decoy tracking IDs & version strings.',
    content: `[2026-11-27T09:14:22Z] INFO  auth-gateway v2.4.1.0 initialized on host 10.24.18.42 (IPv6: 2001:db8:85a3::8a2e:370:7334)
[2026-11-27T09:15:04Z] WARN  ticket=#INC-88412 user="priya.sharma@novacloud.io" src_ip=192.168.14.205 callback="+91 98765 43210"
[2026-11-27T09:15:48Z] INFO  retry payment gateway; fallback_contact="priya.sharma@novacloud.io" phone="+1 (415) 555-0192"
[2026-11-27T09:16:12Z] AUDIT card_primary=4532-0151-1283-0366 card_backup=5425 2334 3010 9903
[2026-11-27T09:16:39Z] DEBUG decoy_order_id=4532-0151-1283-0367 shipment_ref=9876 5432 1098 7654 fw_build=v3.12.0.4
[2026-11-27T09:17:05Z] INFO  ops_escalate="secops-lead@novacloud.io" remote_peer=fe80::1ff:fe23:4567:890a pager=+44 20 7946 0958
[2026-11-27T09:17:51Z] INFO  session closed for priya.sharma@novacloud.io from 192.168.14.205 (trace_id=1111222233334445)`,
  },
  {
    id: 'hr-kyc-record',
    label: 'HR Resume & KYC Record',
    shortLabel: 'HR & KYC',
    extension: 'csv',
    description:
      'Indian PAN cards, spaced/unspaced Aadhaar numbers, +91 & US phone numbers, emails, and a 0-prefixed decoy batch code.',
    content: `candidate_id,full_name,email,mobile,pan_number,aadhaar_number,legacy_batch_code
CAND-101,Aarav Mehta,aarav.mehta@finbridge.in,+91-9820198201,ABCPM1234K,2345 6789 0123,012345678901
CAND-102,Neha Kulkarni,neha.k@veritas-labs.org,(415) 555-0148,BGLPK9821F,345678901234,1987 6543 2109
CAND-103,Aarav Mehta,aarav.mehta@finbridge.in,+91 98201 98201,ABCPM1234K,2345 6789 0123,000011112222
CAND-104,Rohan Verma,rohan.verma@axonworks.co,99887 66554,CHJPV4410A,9876 5432 1098,100020003000`,
  },
  {
    id: 'clinical-billing',
    label: 'Clinical & Billing Note',
    shortLabel: 'Clinical Note',
    extension: 'txt',
    description:
      'Patient & clinician identifiers, repeated contacts, valid Luhn cards, IP audit trails, and invalid invoice decoys.',
    content: `CLINICAL & BILLING AUDIT NOTE — WARD 4B
Attending Physician: Dr. Elena Vance (elena.vance@mercyhealth.org) | Ext/Mobile: 415-555-0183
Patient Record: Vikram Nair | Email: vikram.nair@protonmail.com | Phone: +91 98111 22334
EHR Terminal IP: 172.16.42.88 | Backup Sync Node: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
Insurance PAN on File: AABPN7742M | Aadhaar Verification: 4567 8901 2345
Co-Pay Settlement Card: 4111 1111 1111 1111 (Visa)
Billing Reference (Non-Card Decoy): 4111 1111 1111 1112 | Lab Accession: 8821-4409-3312-9001
Follow-Up Reminder Sent To: vikram.nair@protonmail.com by elena.vance@mercyhealth.org via 172.16.42.88`,
  },
];
