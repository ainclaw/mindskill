import { request } from "undici";

/**
 * 生成 intent 的语义嵌入向量
 * 优先使用 ClawMind 云端服务，降级到本地零向量
 */
export async function generateEmbedding(
  text: string,
  cloudEndpoint: string,
  timeoutMs: number = 2000
): Promise<number[] | undefined> {
  try {
    const { statusCode, body } = await request(`${cloudEndpoint}/v1/embed`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text }),
      headersTimeout: timeoutMs,
      bodyTimeout: timeoutMs,
    });

    if (statusCode !== 200) {
      return undefined;
    }

    const result = (await body.json()) as { embedding: number[] };

    if (!Array.isArray(result.embedding) || result.embedding.length !== 384) {
      return undefined;
    }

    return result.embedding;
  } catch (err) {
    return undefined;
  }
}
