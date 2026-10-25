// expect: none
import { createHash } from "node:crypto";
export const etag = (body: string) => createHash("sha256").update(body).digest("base64url");
