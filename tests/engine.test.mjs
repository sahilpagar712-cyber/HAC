import assert from 'node:assert/strict';
import { isValidLuhn, detectCardNetwork } from '../src/engine/luhn.js';
import { detectPII } from '../src/engine/piiDetector.js';
import {
  createPseudonymSession,
  redactText,
  REDACTION_MODES,
} from '../src/engine/redactor.js';
import { SAMPLE_DATASETS } from '../src/data/sampleDatasets.js';

// 1. Luhn validation tests
assert.equal(isValidLuhn('4532-0151-1283-0366'), true, 'Valid Visa should pass Luhn');
assert.equal(isValidLuhn('5425 2334 3010 9903'), true, 'Valid Mastercard should pass Luhn');
assert.equal(isValidLuhn('3782 822463 10005'), true, 'Valid 15-digit Amex should pass Luhn');
assert.equal(isValidLuhn('4532-0151-1283-0367'), false, 'Invalid Visa decoy must fail Luhn');
assert.equal(isValidLuhn('9876 5432 1098 7654'), false, 'Invalid 16-digit decoy must fail Luhn');
assert.equal(isValidLuhn('0000-0000-0000-0000'), false, 'All-zero 16-digit sequence must be rejected');
assert.equal(isValidLuhn('123456789012'), false, '12-digit number must fail card length gate');
assert.equal(detectCardNetwork('4532-0151-1283-0366'), 'Visa');

// 2. PII detection accuracy & false-positive rejection
const syntheticInput = [
  'email=jane.doe@example.com',
  'phone=+91 98765 43210',
  'us_phone=+1 (415) 555-0192',
  'ip4=192.168.1.45',
  'ver=v2.4.1.0',
  'ip6=2001:db8:85a3::8a2e:370:7334',
  'time=12:34:56',
  'pan=ABCPA1234F',
  'bad_pan=ABCDX1234F',
  'bad_pan_d=ABCDE1234F',
  'aadhaar_spaced=2345 6789 0123',
  'aadhaar_raw=345678901234',
  'bad_aadhaar_0=0123 4567 8901',
  'bad_aadhaar_1=123456789012',
  'card_ok=4111 1111 1111 1111',
  'card_decoy=4111 1111 1111 1112',
].join('\n');

const detection = detectPII(syntheticInput);
const byType = (type) => detection.matches.filter((m) => m.type === type).map((m) => m.value);

assert.deepEqual(byType('EMAIL'), ['jane.doe@example.com']);
assert.deepEqual(byType('PHONE'), ['+91 98765 43210', '+1 (415) 555-0192']);
assert.deepEqual(byType('IP_ADDRESS'), ['192.168.1.45', '2001:db8:85a3::8a2e:370:7334']);
assert.deepEqual(byType('PAN'), ['ABCPA1234F']);
assert.deepEqual(byType('AADHAAR'), ['2345 6789 0123', '345678901234']);
assert.deepEqual(byType('CREDIT_CARD'), ['4111 1111 1111 1111']);
assert.equal(detection.luhnRejectedCount, 1, 'Decoy 16-digit card must increment luhnRejectedCount');

// Ensure non-overlapping offsets
for (let i = 1; i < detection.matches.length; i += 1) {
  assert.ok(
    detection.matches[i].start >= detection.matches[i - 1].end,
    'Matches must be strictly non-overlapping'
  );
}

// 3. Redaction modes verification
const fullMask = redactText(syntheticInput, detection.matches, {
  mode: REDACTION_MODES.FULL_MASK,
});
assert.ok(fullMask.sanitizedText.includes('[REDACTED_EMAIL]'));
assert.ok(fullMask.sanitizedText.includes('[REDACTED_CARD]'));
assert.ok(fullMask.sanitizedText.includes('4111 1111 1111 1112'), 'Non-Luhn decoy must remain untouched');
assert.ok(fullMask.sanitizedText.includes('v2.4.1.0'), 'Version string must remain untouched');

const uniformMask = redactText(syntheticInput, detection.matches, {
  mode: REDACTION_MODES.FULL_MASK,
  uniformFullMask: true,
});
assert.ok(uniformMask.sanitizedText.includes('[REDACTED]'));
assert.ok(!uniformMask.sanitizedText.includes('[REDACTED_EMAIL]'));

const partialMask = redactText(syntheticInput, detection.matches, {
  mode: REDACTION_MODES.PARTIAL_MASK,
});
assert.ok(partialMask.sanitizedText.includes('j***@example.com'));
assert.ok(partialMask.sanitizedText.includes('+91-XXXXXX3210'));
assert.ok(partialMask.sanitizedText.includes('192.168.***.***'));
assert.ok(partialMask.sanitizedText.includes('ABCPA****F'));
assert.ok(partialMask.sanitizedText.includes('XXXX-XXXX-0123'));
assert.ok(partialMask.sanitizedText.includes('XXXX-XXXX-XXXX-1111'));

// 4. Consistent Pseudonymization determinism across repeated values
const repeatedInput =
  'User alice@corp.io called from +91 98765 43210; cc=bob@corp.io; retry alice@corp.io via +91 98765 43210';
const repDetect = detectPII(repeatedInput);
const session = createPseudonymSession();
const pseudo = redactText(repeatedInput, repDetect.matches, {
  mode: REDACTION_MODES.PSEUDONYM,
  session,
});
assert.equal(
  pseudo.sanitizedText,
  'User EMAIL_01 called from PHONE_01; cc=EMAIL_02; retry EMAIL_01 via PHONE_01'
);
assert.equal(session.map.size, 3);

// 5. Sample datasets sanity checks
const serverLogDetect = detectPII(SAMPLE_DATASETS[0].content);
assert.equal(serverLogDetect.countsByType.CREDIT_CARD, 2, 'Server log has 2 valid cards');
assert.equal(serverLogDetect.luhnRejectedCount, 3, 'Server log has 3 non-Luhn 16-digit decoys');
assert.equal(serverLogDetect.countsByType.IP_ADDRESS, 5, 'Server log has 3 IPv4 + 2 IPv6 (v2.4.1.0 & v3.12.0.4 excluded)');

const hrDetect = detectPII(SAMPLE_DATASETS[1].content);
assert.equal(hrDetect.countsByType.PAN, 4);
assert.equal(hrDetect.countsByType.AADHAAR, 4);
assert.equal(hrDetect.luhnRejectedCount, 0);

const clinicalDetect = detectPII(SAMPLE_DATASETS[2].content);
assert.equal(clinicalDetect.countsByType.CREDIT_CARD, 1);
assert.equal(clinicalDetect.luhnRejectedCount, 2);

console.log('ALL REDACTZERO ENGINE TESTS PASSED SUCCESSFULLY.');
