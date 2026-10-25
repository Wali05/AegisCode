// expect: AEG-JS-010
import { createHash } from "node:crypto";
export const hashPassword = (pw: string) => createHash("md5").update(pw).digest("hex");
