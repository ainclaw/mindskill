/**
 * Local PII sanitizer — the primary privacy gate.
 * Runs BEFORE any data leaves the node.
 * Strips all identifiable information from action traces
 * and replaces them with Lobster argument placeholders.
 */

interface SanitizeResult {
  sanitized: string;
  extractedArgs: Map<string, ArgDefinition>;
}

interface ArgDefinition {
  type: "string" | "number" | "boolean";
  placeholder: string;
  originalPattern: string;
}

const PII_RULES: Array<{
  name: string;
  pattern: RegExp;
  argType: "string" | "number";
}> = [
  {
    name: "email",
    pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    argType: "string",
  },
  {
    name: "phone",
    pattern: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    argType: "string",
  },
  {
    name: "card",
    pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
    argType: "string",
  },
  {
    name: "ssn",
    pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
    argType: "string",
  },
  {
    name: "password",
    pattern: /(?:password|passwd|pwd)\s*[:=]\s*\S+/gi,
    argType: "string",
  },
  {
    name: "api_key",
    pattern: /(?:api[_-]?key|token|secret)\s*[:=]\s*[A-Za-z0-9_\-]{16,}/gi,
    argType: "string",
  },
  {
    name: "ip_address",
    pattern: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
    argType: "string",
  },
];

// Common user-input field names that likely contain personal data
const SENSITIVE_FIELD_NAMES = new Set([
  "username",
  "user_name",
  "first_name",
  "last_name",
  "full_name",
  "name",
  "email",
  "phone",
  "address",
  "street",
  "city",
  "zip",
  "zipcode",
  "postal_code",
  "ssn",
  "social_security",
  "credit_card",
  "card_number",
  "cvv",
  "expiry",
  "password",
  "passwd",
  "secret",
  "token",
  "api_key",
  "dob",
  "date_of_birth",
  "birthday",
]);

export function sanitizeTrace(raw: string): SanitizeResult {
  let result = raw;
  const extractedArgs = new Map<string, ArgDefinition>();
  let argCounter = 0;

  // Pass 1: Regex-based PII detection
  for (const rule of PII_RULES) {
    const matches = result.match(rule.pattern);
    if (matches) {
      for (const match of new Set(matches)) {
        const argName = `${rule.name}_${argCounter++}`;
        const placeholder = `$LOBSTER_ARG_${argName.toUpperCase()}`;

        extractedArgs.set(argName, {
          type: rule.argType,
          placeholder,
          originalPattern: rule.name,
        });

        result = result.replaceAll(match, placeholder);
      }
    }
    rule.pattern.lastIndex = 0;
  }

  return { sanitized: result, extractedArgs };
}

export function sanitizeActionArgs(
  args: Record<string, unknown>
): { sanitized: Record<string, unknown>; extractedArgs: Map<string, ArgDefinition> } {
  const allExtracted = new Map<string, ArgDefinition>();
  const sanitized: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(args)) {
    const lowerKey = key.toLowerCase();

    // If the field name itself is sensitive, replace the value entirely
    if (SENSITIVE_FIELD_NAMES.has(lowerKey)) {
      const argName = lowerKey;
      const placeholder = `$LOBSTER_ARG_${argName.toUpperCase()}`;

      allExtracted.set(argName, {
        type: typeof value === "number" ? "number" : "string",
        placeholder,
        originalPattern: `field:${key}`,
      });

      sanitized[key] = placeholder;
      continue;
    }

    // If the value is a string, run PII regex sanitization
    if (typeof value === "string") {
      const { sanitized: cleanValue, extractedArgs } = sanitizeTrace(value);
      sanitized[key] = cleanValue;
      for (const [k, v] of extractedArgs) {
        allExtracted.set(k, v);
      }
    } else {
      sanitized[key] = value;
    }
  }

  return { sanitized, extractedArgs: allExtracted };
}

/**
 * P2: DOM 快照脱敏
 * 移除敏感信息，防止隐私泄露
 */
export function sanitizeDomSnapshot(html: string): string {
  // 移除密码字段
  html = html.replace(
    /<input[^>]*type=["']password["'][^>]*>/gi,
    '<input type="password" value="[REDACTED]">'
  );

  // 移除信用卡号（简单模式：连续 13-19 位数字）
  html = html.replace(/\b\d{13,19}\b/g, "[CARD_REDACTED]");

  // 移除邮箱地址
  html = html.replace(
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    "[EMAIL_REDACTED]"
  );

  // 移除电话号码（国际格式）
  html = html.replace(
    /\+?\d{1,4}?[-.\s]?\(?\d{1,3}?\)?[-.\s]?\d{1,4}[-.\s]?\d{1,4}[-.\s]?\d{1,9}/g,
    "[PHONE_REDACTED]"
  );

  // 移除标记为敏感的元素
  html = html.replace(
    /<[^>]*data-sensitive[^>]*>.*?<\/[^>]+>/gi,
    '<div data-sensitive>[REDACTED]</div>'
  );

  // 移除 SSN（美国社保号）
  html = html.replace(/\b\d{3}-\d{2}-\d{4}\b/g, "[SSN_REDACTED]");

  // 限制快照大小（最多 50KB）
  if (html.length > 50000) {
    html = html.substring(0, 50000) + "\n<!-- TRUNCATED -->";
  }

  return html;
}
