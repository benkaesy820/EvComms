import { z } from 'zod'

// SECURITY FIX: Strengthened password policy
// - Minimum 12 characters (NIST 2024 recommendation)
// - Maximum 128 characters (prevent DoS with extremely long passwords)
// - Block common patterns (sequential, repeated chars)
// - Require mix of character types

// Deduplicated list of common weak passwords
const COMMON_PASSWORDS = new Set([
  'password', '123456', 'qwerty', 'admin', 'letmein', 'welcome', 'monkey', 'dragon',
  'master', 'hello', 'sunshine', 'princess', 'football', 'baseball', 'iloveyou',
  'trustno1', 'abc123', 'password1', '12345678', '123456789', 'adobe123', 'admin123',
  'letmein1', 'photoshop', 'bailey', 'shadow', 'whatever', 'starwars', 'freedom',
  'qazwsx', '654321', '555555', '3rjs1la7qe', 'michelle', 'jessica', 'pepper',
  'zaq12wsx', 'ashley', 'michael', 'ginger', 'tigger', 'matthew', 'amanda',
  'mustang', 'harley', 'chocolate', 'chelsea', 'america', 'thunder', 'patrick',
  'minecraft', 'yankees', 'dallas', 'orioles', 'canada', 'hunter', 'oliver',
  'richard', 'morgan', 'merlin', 'butter', 'cookie', 'falcon', 'ferrari', 'boston',
  'ranger', 'thomas', 'raiders', 'purple', 'andrea', 'bandit', 'heather', 'rachel',
  'qwer1234', 'maggie', 'pretty', 'buster', 'soccer', 'hockey', 'killer', 'george',
  'sexy', 'andrew', 'william', 'robert', 'joshua', 'taylor', 'brian', 'hannah',
  'daniel', 'love', 'nicole', 'biteme', 'babygirl', 'barbara', 'danielle',
  'wrangler', 'xxxxxx', 'lovers', 'nicholas', 'midnight', 'flower'
])

// Build regex from deduplicated set
const commonPasswordsRegex = new RegExp(
  `^(${Array.from(COMMON_PASSWORDS).join('|')})$`,
  'i'
)

const COMMON_PATTERNS = [
  /(.+)\1{2,}/, // Repeated characters (3+ times)
  /^(.)\1+$/, // All same character
  commonPasswordsRegex,
]

export const passwordSchema = z.string()
  .min(12, 'Password must be at least 12 characters')
  .max(128, 'Password must be at most 128 characters')
  .refine(v => /[a-z]/.test(v), 'Must include lowercase letter')
  .refine(v => /[A-Z]/.test(v), 'Must include uppercase letter')
  .refine(v => /\d/.test(v), 'Must include number')
  .refine(v => /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>\/?]/.test(v), 'Must include special character')
  .refine(v => !/\s/.test(v), 'Cannot contain spaces')
  .refine(v => !COMMON_PATTERNS.some(p => p.test(v)), 'Password contains common patterns or is too weak')
  .refine(v => !/012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|ghj|hjk|jkl|zxc|xcv|cvb|vbn|bnm/i.test(v), 'Cannot contain sequential characters')
