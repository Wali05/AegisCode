import { exec } from "child_process";
export function run(c: string) {
  exec("sh -c \"" + c + "\"");
}
